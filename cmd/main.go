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
	saltpm "github.com/salrashid123/oauth2/tpm"

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

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	ctx := context.Background()

	glog.Infof("Starting GCP metadataserver")

	configData, err := os.ReadFile(*configFile)
	if err != nil {
		glog.Errorf("Error reading config data file: %v\n", err)
		os.Exit(-1)
	}

	claims := &mds.Claims{}
	err = json.Unmarshal(configData, claims)
	if err != nil {
		glog.Errorf("Error parsing json: %v\n", err)
		os.Exit(-1)
	}

	var creds *google.Credentials

	// if using TPMs
	var rwc io.ReadWriteCloser
	var handle tpm2.TPMHandle
	var authSession tpmjwt.Session

	_, ok := claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"]
	if !ok {
		glog.Errorf("default service account must be set")
		os.Exit(-1)
	}

	if *useImpersonate {
		glog.Infoln("Using Service Account Impersonation")

		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
			Scopes:          claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
		})
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			os.Exit(1)
		}

		creds = &google.Credentials{
			TokenSource: ts,
		}
	} else if *useFederate {
		glog.Infoln("Using Workload Identity Federation")

		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			glog.Error("GOOGLE_APPLICATION_CREDENTIAL must be set with --federate")
			os.Exit(1)
		}

		glog.Infof("Federation path: %s", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		var err error
		creds, err = google.FindDefaultCredentials(ctx, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			glog.Errorf("Unable load federated credentials %v", err)
			os.Exit(1)
		}
	} else if *useTPM {
		glog.Infoln("Using TPM based token handle")

		// verify we actually have access to the TPM
		rwc, err = OpenTPM(*tpmPath)
		if err != nil {
			glog.Error("can't open TPM %q: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				glog.Error("can't close TPM %q: %v", *tpmPath, err)
				os.Exit(1)
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
				os.Exit(1)
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
				os.Exit(1)
			}
		}

		// configure a session
		if *pcrs != "" {
			// parse TPM PCR values (if set)
			var pcrList = []uint{}
			strpcrs := strings.Split(*pcrs, ",")
			for _, i := range strpcrs {
				j, err := strconv.Atoi(i)
				if err != nil {
					glog.Error("ERROR:  could convert pcr value: %v", err)
					os.Exit(1)
				}
				pcrList = append(pcrList, uint(j))
			}

			authSession, err = tpmjwt.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			})
			if err != nil {
				glog.Error(os.Stderr, "error creating tpm pcrsession %v\n", err)
				os.Exit(1)
			}

		} else if *keyPass != "" {
			authSession, err = tpmjwt.NewPasswordSession(rwr, []byte(*keyPass))
			if err != nil {
				glog.Error(os.Stderr, "error creating tpm passwordsession%v\n", err)
				os.Exit(1)
			}
		}

		var ts oauth2.TokenSource
		// either load the tpm key from disk or persistent handle
		if *tpmKeyFile != "" {

			c, err := os.ReadFile(*tpmKeyFile)
			if err != nil {
				glog.Error("can't load tpmkeyfile: %v", err)
				os.Exit(1)
			}
			key, err := keyfile.Decode(c)
			if err != nil {
				glog.Error("can't decode tpmkeyfile: %v", err)
				os.Exit(1)
			}

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
				os.Exit(1)
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
				os.Exit(1)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			glog.V(40).Infof("TPM credentials using using Key handle %d", rsaKey.ObjectHandle)
			ts, err = saltpm.TpmTokenSource(&saltpm.TpmTokenConfig{
				TPMDevice:        rwc,
				Handle:           rsaKey.ObjectHandle,
				AuthSession:      authSession,
				Email:            claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Scopes:           claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
				EncryptionHandle: encryptionSessionHandle,
			})
			if err != nil {
				glog.Error(os.Stderr, "error creating tpm tokensource%v\n", err)
				os.Exit(1)
			}

			handle = rsaKey.ObjectHandle

		} else if *persistentHandle > 0 {
			glog.V(40).Infof("TPM credentials using using persistent handle %d", *persistentHandle)

			ts, err = saltpm.TpmTokenSource(&saltpm.TpmTokenConfig{
				TPMDevice:        rwc,
				Handle:           tpm2.TPMHandle(*persistentHandle), // persistent handle
				AuthSession:      authSession,
				Email:            claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Scopes:           claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
				EncryptionHandle: encryptionSessionHandle,
			})
			if err != nil {
				glog.Error(os.Stderr, "error creating tpm tokensource%v\n", err)
				os.Exit(1)
			}
			handle = tpm2.TPMHandle(*persistentHandle)
		} else {
			glog.Error("Must specify either a persistent handle or a keyfile for use with at TPM")
			os.Exit(1)
		}

		creds = &google.Credentials{
			ProjectID:   claims.ComputeMetadata.V1.Project.ProjectID,
			TokenSource: ts,
		}
	} else {

		glog.Infoln("Using serviceAccountFile for credentials")
		var err error
		data, err := os.ReadFile(*serviceAccountFile)
		if err != nil {
			glog.Errorf("Unable to read serviceAccountFile %v", err)
			os.Exit(1)
		}
		creds, err = google.CredentialsFromJSON(ctx, data, claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			glog.Errorf("Unable to parse serviceAccountFile %v ", err)
			os.Exit(1)
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
			os.Exit(1)
		}
		credFileEmail := credJsonMap["client_email"]
		if credFileEmail != claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email {
			glog.Warningf("Warning: service account email in config file [%s] does not match project from credentials [%s]", claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email, credFileEmail)
		}

	}

	if *usemTLS && (*rootCAmTLS == "" || *serverCert == "" || *serverKey == "") {
		if err != nil {
			glog.Errorf("Must specify rootCAmTLS, serverCert and serverKey if useMTLS is set")
			os.Exit(1)
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
	}

	f, err := mds.NewMetadataServer(ctx, serverConfig, creds, claims)
	if err != nil {
		glog.Errorf("Error creating metadata server %v\n", err)
		os.Exit(1)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		glog.Errorf("Error creating file watcher: %v\n", err)
		os.Exit(1)
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
					if event.Name == *configFile {
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
		os.Exit(1)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	err = f.Start()
	if err != nil {
		glog.Errorf("Error starting %v\n", err)
		os.Exit(1)
	}
	<-done
	err = f.Shutdown()
	if err != nil {
		glog.Errorf("Error stopping %v\n", err)
		os.Exit(1)
	}
}
