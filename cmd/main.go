package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"log/slog"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/fsnotify/fsnotify"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	mds "github.com/salrashid123/gce_metadata_server"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	tpmmtls "github.com/salrashid123/mtls-tokensource/tpm"
	tpmoauth "github.com/salrashid123/oauth2/v3"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
)

var (
	bindInterface      = flag.String("interface", "127.0.0.1", "interface address to bind to")
	port               = flag.String("port", ":8080", "port...")
	useDomainSocket    = flag.String("domainsocket", "", "listen only on unix socket")
	serviceAccountFile = flag.String("serviceAccountFile", "", "serviceAccountFile...")
	configFile         = flag.String("configFile", "config.json", "config file")
	useImpersonate     = flag.Bool("impersonate", false, "Impersonate a service Account instead of using the keyfile")
	useFederate        = flag.Bool("federate", false, "Use Workload Identity Federation ADC")

	metricsEnabled   = flag.Bool("metricsEnabled", false, "Enable prometheus metrics endpoint")
	metricsInterface = flag.String("metricsInterface", "127.0.0.1", "metrics interface address to bind to")
	metricsPort      = flag.String("metricsPort", "9000", "metrics port to bind to")
	metricsPath      = flag.String("metricsPath", "/metrics", "metrics path to use")

	useTPM                = flag.Bool("tpm", false, "Use TPM to get access and id_token")
	persistentHandle      = flag.Int("persistentHandle", 0, "Handle value")
	tpmKeyFile            = flag.String("keyfile", "", "TPM Encrypted private key")
	tpmPath               = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	parentPass            = flag.String("parentPass", "", "TPM Parent Key password")
	keyPass               = flag.String("keyPass", "", "TPM Key password")
	pcrs                  = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	useOauthToken         = flag.Bool("useOauthToken", false, "Use oauth2 token instead of jwtAccessToken (default: false)")
	useEKParent           = flag.Bool("useEKParent", false, "Use endorsement RSAKey as parent (not h2) (default: false)")
	useTPMmTLS            = flag.Bool("useTPMmTLS", false, "Use TPM based workload federation mtls (default: false)")
	projectNumber         = flag.String("projectNumber", "", "Project Number for mTLS (default: )")
	poolID                = flag.String("poolID", "", "workload identity pool id for mTLS (default: )")
	providerID            = flag.String("providerID", "", "workload identity pool id for mTLS (default: )")
	pubCert               = flag.String("pubCert", "", "workload identity public certificate for mTLS (default: )")

	logTarget = flag.String("logTarget", "", "log to file target (default stdout)")
	jsonLog   = flag.Bool("jsonLog", false, "enable json logging")
	debug     = flag.Bool("debug", false, "enable debug logging")

	usemTLS           = flag.Bool("usemTLS", false, "Use mTLS")
	rootCAmTLS        = flag.String("rootCAmTLS", "certs/root.crt", "rootCA to validate client certs ")
	serverCert        = flag.String("serverCert", "certs/server.crt", "Server mtls certificate")
	serverKey         = flag.String("serverKey", "certs/server.key", "Server mtls key")
	version           = flag.Bool("version", false, "print version")
	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
		// } else if path == "simulator" {
		// 	return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		return 0
	}

	ctx := context.Background()

	var logger *slog.Logger
	mlogTarget := os.Stdout // default
	if *logTarget != "" {
		var err error
		mlogTarget, err = os.OpenFile(*logTarget, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Error("Failed to open log file", "err", err)
			return -1
		}
	}
	defer mlogTarget.Close()

	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	if *jsonLog {
		logger = slog.New(slog.NewJSONHandler(mlogTarget, &slog.HandlerOptions{
			Level: logLevel,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(mlogTarget, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}

	logger.Info("Starting GCP metadataserver", slog.Group("build", slog.String("version", Tag), slog.String("date", Date), slog.String("commit", Commit)))

	configData, err := os.ReadFile(*configFile)
	if err != nil {
		logger.Error("error reading config data file", slog.String("raw_error", err.Error()))
		return -1
	}

	claims := &mds.Claims{}
	err = json.Unmarshal(configData, claims)
	if err != nil {
		logger.Error("error parsing config data file", slog.String("raw_error", err.Error()))
		return -1
	}

	var creds *google.Credentials

	// if using TPMs
	var rwc io.ReadWriteCloser
	var handle tpm2.TPMHandle
	var authSession tpmjwt.Session

	_, ok := claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"]
	if !ok {
		logger.Error("default service account must be set", slog.String("raw_error", ""))
		return -1
	}

	if *useImpersonate {
		logger.Info("Using Service Account Impersonation for credentials")

		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
			Scopes:          claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
		})
		if err != nil {
			logger.Error("Unable to create Impersonated TokenSource", slog.String("raw_error", err.Error()))
			return -1
		}
		logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "impersonated_credential"), slog.String("target_principal", claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email), slog.String("scopes", strings.Join(claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes, " "))))
		creds = &google.Credentials{
			TokenSource: ts,
		}
	} else if *useFederate {
		logger.Info("Using Workload Identity Federation for credentials")

		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			logger.Error("GOOGLE_APPLICATION_CREDENTIAL must be set with --federate", slog.String("raw_error", ""))
			return -1
		}

		logger.Info("credential_configuration", slog.Group("credential", "type", "federated_credential", "federation_path", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))
		var err error
		creds, err = google.FindDefaultCredentials(ctx, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			logger.Error("Unable load federated credentials", slog.String("raw_error", err.Error()))
			return -1
		}
	} else if *useTPM {
		logger.Info("Using TPM for credentials")

		// verify we actually have access to the TPM
		rwc, err = OpenTPM(*tpmPath)
		if err != nil {
			logger.Error("can't open TPM", slog.String("raw_error", err.Error()))
			return -1
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				logger.Error("can't close TPM", slog.String("raw_error", err.Error()))
				return
			}
		}()
		rwr := transport.FromReadWriter(rwc)

		// setup the EK for use with encrypted sessions to the TPM
		var encryptionSessionHandle tpm2.TPMHandle

		if *sessionEncryptionName != "" {
			createEKCmd := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}
			createEKRsp, err := createEKCmd.Execute(rwr)
			if err != nil {
				logger.Error("can't acquire acquire ek", slog.String("raw_error", err.Error()))
				return -1
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: createEKRsp.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			encryptionSessionHandle = createEKRsp.ObjectHandle
			if *sessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
				logger.Error("session encryption names do not match", slog.String("got", *sessionEncryptionName), slog.String("expected", hex.EncodeToString(createEKRsp.Name.Buffer)))
				return -1
			}
		}

		// configure a session
		if *pcrs != "" {
			// parse TPM PCR values (if set)

			// todo, support pcrbanks and expected values
			//   eg --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
			// pcrMap := make(map[uint][]byte)
			// for _, v := range strings.Split(*pcrValues, ",") {
			// 	entry := strings.Split(v, ":")
			// 	if len(entry) == 2 {
			// 		uv, err := strconv.ParseUint(entry[0], 10, 32)
			// 		if err != nil {
			// 			logger.Error("Error parsing PCRs", slog.String("raw_error", err.Error()))
			// 			return -1
			// 		}
			// 		hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			// 		if err != nil {
			// 			logger.Error("error decoding pcr Hex values",slog.String("raw_error", err.Error()))
			// 			return -1
			// 		}
			// 		pcrMap[uint(uv)] = hexEncodedPCR
			// 	}
			// }

			// // calculate the pcrHash
			// hsh := sha256.New()
			// for _, v := range pcrMap {
			// 	_, err := hsh.Write(v)
			// 	if err != nil {
			// 		logger.Error("error calculating hash",slog.String("raw_error", err.Error()))
			// 		return -1
			// 	}
			// }
			// pcrList := make([]uint, 0, len(pcrMap))
			// for k := range pcrMap {
			// 	pcrList = append(pcrList, k)
			// }

			// pcrHash := hsh.Sum(nil)

			var pcrList = []uint{}
			strpcrs := strings.Split(*pcrs, ",")
			for _, i := range strpcrs {
				j, err := strconv.Atoi(i)
				if err != nil {
					logger.Error("could convert pcr value", slog.String("raw_error", err.Error()))
					return -1
				}
				pcrList = append(pcrList, uint(j))
			}

			if *useEKParent {
				primaryKey, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHEndorsement,
					InPublic:      tpm2.New2B(tpm2.RSAEKTemplate), // TODO: allow ECEKTemplate
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't create pimaryEK", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: primaryKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()

				sel := []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					}}
				authSession, err = tpmjwt.NewPCRAndDuplicateSelectSession(rwr, sel, tpm2.TPM2BDigest{}, []byte(*keyPass), primaryKey.Name, encryptionSessionHandle)
				if err != nil {
					logger.Error("can't create autsession", slog.String("raw_error", err.Error()))
					return -1
				}
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)

			} else {

				authSession, err = tpmjwt.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					},
				}, tpm2.TPM2BDigest{}, encryptionSessionHandle)
				if err != nil {
					logger.Error("error creating tpm pcrsession", slog.String("raw_error", err.Error()))
					return -1
				}
			}

		} else if *keyPass != "" {
			if *useEKParent {
				primaryKey, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHEndorsement,
					InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't create pimaryEK", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: primaryKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()

				authSession, err = tpmjwt.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*keyPass), primaryKey.Name, encryptionSessionHandle)
				if err != nil {
					logger.Error("can't create autsession", slog.String("raw_error", err.Error()))
					return -1
				}
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)

			} else {
				authSession, err = tpmjwt.NewPasswordAuthSession(rwr, []byte(*keyPass), encryptionSessionHandle)
				if err != nil {
					logger.Error("error creating tpm passwordsession", slog.String("raw_error", err.Error()))
					return -1
				}
			}
		}

		var ts oauth2.TokenSource
		// either load the tpm key from disk or persistent handle
		if *tpmKeyFile != "" {

			c, err := os.ReadFile(*tpmKeyFile)
			if err != nil {
				logger.Error("can't load tpmkeyfile", slog.String("raw_error", err.Error()))
				return -1
			}
			key, err := keyfile.Decode(c)
			if err != nil {
				logger.Error("can't decode tpmkeyfile", slog.String("raw_error", err.Error()))
				return -1
			}
			if *useEKParent {

				primaryKey, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHEndorsement,
					InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't create pimaryEK", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: primaryKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()
				load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
				if err != nil {
					logger.Error("can't load policysession", slog.String("raw_error", err.Error()))
					return -1
				}
				defer load_session_cleanup()

				_, err = tpm2.PolicySecret{
					AuthHandle: tpm2.AuthHandle{
						Handle: tpm2.TPMRHEndorsement,
						Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
						Auth:   tpm2.PasswordAuth([]byte(*parentPass)),
					},
					PolicySession: load_session.Handle(),
					NonceTPM:      load_session.NonceTPM(),
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't create policysecret", slog.String("raw_error", err.Error()))
					return -1
				}

				rsaKey, err := tpm2.Load{
					ParentHandle: tpm2.AuthHandle{
						Handle: primaryKey.ObjectHandle,
						Name:   tpm2.TPM2BName(primaryKey.Name),
						Auth:   load_session,
					},
					InPublic:  key.Pubkey,
					InPrivate: key.Privkey,
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't load key", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: rsaKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()

				handle = rsaKey.ObjectHandle

			} else {
				/*
					Template for the H2 h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

					for use with KeyFiles described in 	[ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)

					printf '\x00\x00' > unique.dat
					tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
				*/
				primaryKey, err := tpm2.CreatePrimary{
					PrimaryHandle: key.Parent,
					InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
				}.Execute(rwr)
				if err != nil {
					logger.Error("can't create primary", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: primaryKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()

				rsaKey, err := tpm2.Load{
					ParentHandle: tpm2.AuthHandle{
						Handle: primaryKey.ObjectHandle,
						Name:   tpm2.TPM2BName(primaryKey.Name),
						Auth:   tpm2.PasswordAuth([]byte(*parentPass)),
					},
					InPublic:  key.Pubkey,
					InPrivate: key.Privkey,
				}.Execute(rwr)

				if err != nil {
					logger.Error("exception loading TPM key", slog.String("raw_error", err.Error()))
					return -1
				}

				defer func() {
					flushContextCmd := tpm2.FlushContext{
						FlushHandle: rsaKey.ObjectHandle,
					}
					_, _ = flushContextCmd.Execute(rwr)
				}()
				handle = rsaKey.ObjectHandle
			}

		} else if *persistentHandle > 0 {
			logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "tpm_credential"), slog.String("persistent_handle", strconv.FormatUint(uint64(*persistentHandle), 16))))
			handle = tpm2.TPMHandle(*persistentHandle)
		} else {
			logger.Error("Must specify either a persistent handle or a keyfile for use with at TPM", slog.String("raw_error", err.Error()))
			return -1
		}

		pub, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(rwr)
		if err != nil {
			logger.Error("error reading persistentHandle public from TPM", slog.String("raw_error", err.Error()))
			return -1
		}
		logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "tpm_credential"), slog.String("service_account_email", claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email), slog.String("tpm_credentials name", hex.EncodeToString(pub.Name.Buffer))))

		if *useTPMmTLS {
			if *poolID == "" || *providerID == "" || *pubCert == "" {
				logger.Error("both ProjectNumber, ProviderID PoolID must be specified for mtls", slog.String("raw_error", ""))
				return -1
			}

			logger.Info("Using TPM with mTLS Workload Identity Federation for credentials")

			numericprojectID := strconv.FormatInt(claims.ComputeMetadata.V1.Project.NumericProjectID, 10)

			if *projectNumber != "" {
				numericprojectID = *projectNumber
			}

			certPEMBlock, err := os.ReadFile(*pubCert)
			if err != nil {
				logger.Error("failed to read certificate file", slog.String("raw_error", err.Error()))
				return -1
			}

			// Decode the PEM block
			block, _ := pem.Decode(certPEMBlock)
			if block == nil || block.Type != "CERTIFICATE" {
				logger.Error("failed to decode PEM block as certificate", slog.String("raw_error", ""))
				return -1
			}

			// Parse the X.509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Error("failed to parse certificate", slog.String("raw_error", err.Error()))
				return -1
			}

			audience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", numericprojectID, *poolID, *providerID)
			ts, err = tpmmtls.TpmMTLSTokenSource(&tpmmtls.TpmMtlsTokenConfig{
				TPMDevice:       rwc,
				Handle:          handle,
				Audience:        audience,
				X509Certificate: cert,
			})
			if err != nil {
				logger.Error("exception creating tpm tokensource", slog.String("raw_error", err.Error()))
				return -1
			}
			logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "tpm_mtls_credential"), slog.String("audience", audience)))
			creds = &google.Credentials{
				ProjectID:   claims.ComputeMetadata.V1.Project.ProjectID,
				TokenSource: ts,
			}
		} else {
			ts, err = tpmoauth.TpmTokenSource(&tpmoauth.TpmTokenConfig{
				TPMDevice:        rwc,
				Handle:           handle,
				AuthSession:      authSession,
				Email:            claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Scopes:           claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
				EncryptionHandle: encryptionSessionHandle,
				UseOauthToken:    *useOauthToken,
			})
			if err != nil {
				logger.Error("error creating tpm tokensource", slog.String("raw_error", err.Error()))
				return -1
			}
			creds = &google.Credentials{
				ProjectID:   claims.ComputeMetadata.V1.Project.ProjectID,
				TokenSource: ts,
			}
		}

	} else if *serviceAccountFile != "" {

		logger.Info("Using serviceAccountFile for credentials")
		var err error
		data, err := os.ReadFile(*serviceAccountFile)
		if err != nil {
			logger.Error("Unable to read serviceAccountFile", slog.String("raw_error", err.Error()))
			return -1
		}
		creds, err = google.CredentialsFromJSON(ctx, data, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			logger.Error("Unable to parse serviceAccountFile", slog.String("raw_error", err.Error()))
			return -1
		}

		if creds.ProjectID != claims.ComputeMetadata.V1.Project.ProjectID {
			logger.Warn("ProjectID in config file does not match project from credentials", slog.String("from_config_file", claims.ComputeMetadata.V1.Project.ProjectID), slog.String("from_credentials", creds.ProjectID))
		}

		// compare the svc account email in the cred file vs the config file
		//       note json struct for the service account file isn't exported  https://github.com/golang/oauth2/blob/master/google/google.go#L109
		// for now i'm parsing it directly
		credJsonMap := make(map[string](interface{}))
		err = json.Unmarshal(creds.JSON, &credJsonMap)
		if err != nil {
			logger.Error("Unable to parse serviceAccountFile as json", slog.String("raw_error", err.Error()))
			return -1
		}
		credFileEmail, ok := credJsonMap["client_email"].(string)
		if !ok {
			logger.Error("invalid client_email type; must be string", slog.String("raw_error", ""))
			return -1
		}

		if credFileEmail != claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email {
			logger.Warn("service account email in config file does not match project from credentials", slog.String("from_config_file", claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email), slog.String("from_credentials", credFileEmail))
		}

		logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "service_account_credential"), slog.String("path", *serviceAccountFile), slog.String("service_account_email", credFileEmail), slog.String("scopes", strings.Join(claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes, " "))))

	} else {
		logger.Info("Using environment variables for credentials")
		if os.Getenv("GOOGLE_ACCESS_TOKEN") == "" || os.Getenv("GOOGLE_ID_TOKEN") == "" || os.Getenv("GOOGLE_PROJECT_ID") == "" || os.Getenv("GOOGLE_NUMERIC_PROJECT_ID") == "" || os.Getenv("GOOGLE_SERVICE_ACCOUNT") == "" {
			logger.Error("Environment variables must be set: GOOGLE_ID_TOKEN,  GOOGLE_ACCESS_TOKEN,  GOOGLE_PROJECT_ID,  GOOGLE_NUMERIC_PROJECT_ID,  GOOGLE_SERVICE_ACCOUNT", slog.String("raw_error", ""))
			return -1
		}
		ts := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: os.Getenv(os.Getenv("GOOGLE_ACCESS_TOKEN")),
			Expiry:      time.Now().Add(time.Second * 3600),
			TokenType:   "Bearer",
		})
		logger.Info("credential_configuration", slog.Group("credential", slog.String("type", "static_credential"), slog.String("GOOGLE_SERVICE_ACCOUNT", os.Getenv("GOOGLE_SERVICE_ACCOUNT"))))
		creds = &google.Credentials{
			ProjectID:   os.Getenv("GOOGLE_PROJECT_ID"),
			TokenSource: ts,
		}
	}

	if *usemTLS && (*rootCAmTLS == "" || *serverCert == "" || *serverKey == "") {
		if err != nil {
			logger.Error("Must specify rootCAmTLS, serverCert and serverKey if useMTLS is set", slog.String("raw_error", err.Error()))
			return -1
		}
	}

	serverConfig := &mds.ServerConfig{
		BindInterface:    *bindInterface,
		Port:             *port,
		Impersonate:      *useImpersonate,
		Federate:         *useFederate,
		DomainSocket:     *useDomainSocket,
		UseTPM:           *useTPM,
		UseTPMmTLS:       *useTPMmTLS,
		TPMDevice:        rwc,
		Handle:           handle,
		AuthSession:      authSession,
		MetricsEnabled:   *metricsEnabled,
		MetricsInterface: *metricsInterface,
		MetricsPort:      *metricsPort,
		MetricsPath:      *metricsPath,
		UsemTLS:          *usemTLS,
		RootCAmTLS:       *rootCAmTLS,
		ServerCert:       *serverCert,
		ServerKey:        *serverKey,
		Logger:           logger,
		Tag:              Tag,
	}

	f, err := mds.NewMetadataServer(ctx, serverConfig, creds, claims)
	if err != nil {
		logger.Error("exception creating metadata server", slog.String("raw_error", err.Error()))
		return -1
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("exception creating file watcher", slog.String("raw_error", err.Error()))
		return -1
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Has(fsnotify.Write) {
					if event.Name == fmt.Sprintf("%s/%s", filepath.Dir(*configFile), filepath.Base(*configFile)) {
						time.Sleep(8 * time.Millisecond) // https://github.com/fsnotify/fsnotify/issues/372
						configData, err := os.ReadFile(*configFile)
						if err != nil {
							logger.Error("exception reading configFile", "raw_error", slog.String("raw_error", err.Error()))
							return
						}

						claims := &mds.Claims{}
						err = json.Unmarshal(configData, claims)
						if err != nil {
							slog.Error("exception parsing json", slog.String("raw_error", err.Error()))
							return
						}
						logger.Info("configFile updated")
						f.Claims = *claims
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error("exception on file_watcher", slog.String("raw_error", err.Error()))
			}
		}
	}()

	err = watcher.Add(filepath.Dir(*configFile))
	if err != nil {
		logger.Error("exception watching configFile", slog.String("raw_error", err.Error()))
		return -1
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	err = f.Start()
	if err != nil {
		logger.Error("starting server exception", slog.String("raw_error", err.Error()))
		return -1
	}
	<-done
	err = f.Shutdown()
	if err != nil {
		logger.Error("stopping server exception", slog.String("raw_error", err.Error()))
		return -1
	}
	return 0
}
