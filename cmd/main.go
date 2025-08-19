package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
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

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/fsnotify/fsnotify"
	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	mds "github.com/salrashid123/gce_metadata_server"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
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

	glog.Infof("Starting GCP metadataserver")

	configData, err := os.ReadFile(*configFile)
	if err != nil {
		glog.Errorf("Error reading config data file: %v\n", err)
		return -1
	}

	claims := &mds.Claims{}
	err = json.Unmarshal(configData, claims)
	if err != nil {
		glog.Errorf("Error parsing json: %v\n", err)
		return -1
	}

	var creds *google.Credentials

	// if using TPMs
	var rwc io.ReadWriteCloser
	var handle tpm2.TPMHandle
	var authSession tpmjwt.Session

	_, ok := claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"]
	if !ok {
		glog.Errorf("default service account must be set")
		return -1
	}

	if *useImpersonate {
		glog.Infoln("Using Service Account Impersonation for credentials")

		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
			Scopes:          claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
		})
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			return -1
		}

		creds = &google.Credentials{
			TokenSource: ts,
		}
	} else if *useFederate {
		glog.Infoln("Using Workload Identity Federation for credentials")

		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			glog.Error("GOOGLE_APPLICATION_CREDENTIAL must be set with --federate")
			return -1
		}

		glog.Infof("Federation path: %s", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		var err error
		creds, err = google.FindDefaultCredentials(ctx, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			glog.Errorf("Unable load federated credentials %v", err)
			return -1
		}
	} else if *useTPM {
		glog.Infoln("Using TPM for credentials")

		// verify we actually have access to the TPM
		rwc, err = OpenTPM(*tpmPath)
		if err != nil {
			glog.Error("can't open TPM %q: %v", *tpmPath, err)
			return -1
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				glog.Error("can't close TPM %q: %v", *tpmPath, err)
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
				glog.Error(os.Stderr, "can't acquire acquire ek %v", err)
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
				glog.Errorf("session encryption names do not match expected [%s] got [%s]", *sessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
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
			// 			glog.Error("Error parsing PCRs %v", err)
			// 			return -1
			// 		}
			// 		hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			// 		if err != nil {
			// 			glog.Error("error decoding pcr Hex values %v", err)
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
			// 		glog.Error("error calculating hash %v", err)
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
					glog.Error("ERROR:  could convert pcr value: %v", err)
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
					glog.Error("can't create pimaryEK: %v", err)
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
					glog.Error("can't create autsession: %v", err)
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
					glog.Error(os.Stderr, "error creating tpm pcrsession %v\n", err)
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
					glog.Error("can't create pimaryEK: %v", err)
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
					glog.Error("can't create autsession: %v", err)
					return -1
				}
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)

			} else {
				authSession, err = tpmjwt.NewPasswordAuthSession(rwr, []byte(*keyPass), encryptionSessionHandle)
				if err != nil {
					glog.Error(os.Stderr, "error creating tpm passwordsession%v\n", err)
					return -1
				}
			}
		}

		var ts oauth2.TokenSource
		// either load the tpm key from disk or persistent handle
		if *tpmKeyFile != "" {

			c, err := os.ReadFile(*tpmKeyFile)
			if err != nil {
				glog.Error("can't load tpmkeyfile: %v", err)
				return -1
			}
			key, err := keyfile.Decode(c)
			if err != nil {
				glog.Error("can't decode tpmkeyfile: %v", err)
				return -1
			}
			if *useEKParent {

				primaryKey, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHEndorsement,
					InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
				}.Execute(rwr)
				if err != nil {
					glog.Error("can't create pimaryEK: %v", err)
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
					glog.Error("can't load policysession : %v", err)
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
					glog.Error("can't create policysecret: %v", err)
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
					glog.Error("can't load key: %v", err)
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
					glog.Error("can't create primary: %v", err)
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
					glog.Error("can't loading key: %v", err)
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
			glog.V(40).Infof("TPM credentials using using persistent handle 0x%s", strconv.FormatUint(uint64(*persistentHandle), 16))

			handle = tpm2.TPMHandle(*persistentHandle)

		} else {
			glog.Error("Must specify either a persistent handle or a keyfile for use with at TPM")
			return -1
		}

		pub, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(rwr)
		if err != nil {
			glog.Error(os.Stderr, "error reading persistentHandle public from TPM: %v\n", err)
			return -1
		}
		glog.V(40).Infof("TPM credentials name %s", hex.EncodeToString(pub.Name.Buffer))

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
			glog.Error(os.Stderr, "error creating tpm tokensource%v\n", err)
			return -1
		}
		creds = &google.Credentials{
			ProjectID:   claims.ComputeMetadata.V1.Project.ProjectID,
			TokenSource: ts,
		}
	} else if *serviceAccountFile != "" {

		glog.Infoln("Using serviceAccountFile for credentials")
		var err error
		data, err := os.ReadFile(*serviceAccountFile)
		if err != nil {
			glog.Errorf("Unable to read serviceAccountFile %v", err)
			return -1
		}
		creds, err = google.CredentialsFromJSON(ctx, data, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			glog.Errorf("Unable to parse serviceAccountFile %v ", err)
			return -1
		}

		if creds.ProjectID != claims.ComputeMetadata.V1.Project.ProjectID {
			glog.Warningf("Warning: ProjectID in config file [%s] does not match project from credentials [%s]", claims.ComputeMetadata.V1.Project.ProjectID, creds.ProjectID)
		}

		// compare the svc account email in the cred file vs the config file
		//       note json struct for the service account file isn't exported  https://github.com/golang/oauth2/blob/master/google/google.go#L109
		// for now i'm parsing it directly
		credJsonMap := make(map[string](interface{}))
		err = json.Unmarshal(creds.JSON, &credJsonMap)
		if err != nil {
			glog.Errorf("Unable to parse serviceAccountFile as json %v ", err)
			return -1
		}
		credFileEmail := credJsonMap["client_email"]
		if credFileEmail != claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email {
			glog.Warningf("Warning: service account email in config file [%s] does not match project from credentials [%s]", claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email, credFileEmail)
		}
	} else {
		glog.Infoln("Using environment variables for credentials")
		if os.Getenv("GOOGLE_ACCESS_TOKEN") == "" || os.Getenv("GOOGLE_ID_TOKEN") == "" || os.Getenv("GOOGLE_PROJECT_ID") == "" || os.Getenv("GOOGLE_NUMERIC_PROJECT_ID") == "" || os.Getenv("GOOGLE_SERVICE_ACCOUNT") == "" {
			glog.Errorf("Environment variables must be set: GOOGLE_ID_TOKEN,  GOOGLE_ACCESS_TOKEN,  GOOGLE_PROJECT_ID,  GOOGLE_NUMERIC_PROJECT_ID,  GOOGLE_SERVICE_ACCOUNT")
			return -1
		}
		ts := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: os.Getenv(os.Getenv("GOOGLE_ACCESS_TOKEN")),
			Expiry:      time.Now().Add(time.Second * 3600),
			TokenType:   "Bearer",
		})
		creds = &google.Credentials{
			ProjectID:   os.Getenv("GOOGLE_PROJECT_ID"),
			TokenSource: ts,
		}
	}

	if *usemTLS && (*rootCAmTLS == "" || *serverCert == "" || *serverKey == "") {
		if err != nil {
			glog.Errorf("Must specify rootCAmTLS, serverCert and serverKey if useMTLS is set")
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
		Tag:              Tag,
	}

	f, err := mds.NewMetadataServer(ctx, serverConfig, creds, claims)
	if err != nil {
		glog.Errorf("Error creating metadata server %v\n", err)
		return -1
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		glog.Errorf("Error creating file watcher: %v\n", err)
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
							glog.Errorf("Error reading configFile: %v\n", err)
							return
						}

						claims := &mds.Claims{}
						err = json.Unmarshal(configData, claims)
						if err != nil {
							glog.Errorf("Error parsing json: %v\n", err)
							return
						}
						glog.V(10).Infoln("configFile updated")
						f.Claims = *claims
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				glog.Errorf("Error on filewatcher %v\n", err)
			}
		}
	}()

	err = watcher.Add(filepath.Dir(*configFile))
	if err != nil {
		glog.Errorf("Error watching configFile: %v\n", err)
		return -1
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	err = f.Start()
	if err != nil {
		glog.Errorf("Error starting %v\n", err)
		return -1
	}
	<-done
	err = f.Shutdown()
	if err != nil {
		glog.Errorf("Error stopping %v\n", err)
		return -1
	}
	return 0
}
