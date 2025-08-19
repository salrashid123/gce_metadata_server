package mds

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/gorilla/mux"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"

	"cloud.google.com/go/compute/metadata"
	saltpm "github.com/salrashid123/oauth2/v3"
)

func getFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "127.0.0.1:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

func addHeaders(req http.Request) http.Request {
	req.Header.Set("Metadata-Flavor", "Google")
	req.Header.Set("Host", "metadata.google.internal")
	return req
}

func verifyResponseHeaders(resp http.Response) error {
	if resp.Header.Get("Server") != "Metadata Server for VM" {
		return fmt.Errorf("Response Server check failed, expected  %s  got %s", "Metadata Server for VM", resp.Header.Get("Server"))
	}
	if resp.Header.Get("Metadata-Flavor") != "Google" {
		return fmt.Errorf("Response Metadata-Flavor check failed, expected %s got %s", "Google", resp.Header.Get("Metadata-Flavor"))
	}
	if resp.Header.Get("X-XSS-Protection") != "0" {
		return fmt.Errorf("Response X-XSS-Protection check failed, expected %s got %s", "0", resp.Header.Get("X-XSS-Protection"))
	}
	if resp.Header.Get("X-Frame-Options") != "SAMEORIGIN" {
		return fmt.Errorf("Response X-Frame-Options check failed, expected %s got %s", "SAMEORIGIN", resp.Header.Get("X-Frame-Options"))
	}
	return nil
}

func TestBasePathRedirectHandler(t *testing.T) {

	h := &MetadataServer{}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	addHeaders(*req)
	rr := httptest.NewRecorder()
	handler := h.checkMetadataHeaders(http.HandlerFunc(h.handleBasePathRedirect))
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusMovedPermanently {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMovedPermanently)
	}

	err = verifyResponseHeaders(*rr.Result())
	if err != nil {
		t.Errorf("handler returned unexpected header: got %v", err)
	}

	expected := "/\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

// TODO:  test all other endpoints.
func TestProjectIDHandler(t *testing.T) {
	expectedProjectID := "some-project-id"
	h := &MetadataServer{
		Claims: Claims{
			ComputeMetadata: ComputeMetadata{
				V1: V1{
					Project: Project{
						ProjectID: expectedProjectID,
					},
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "/computeMetadata/v1/project/project-id", nil)
	if err != nil {
		t.Fatal(err)
	}

	addHeaders(*req)
	rr := httptest.NewRecorder()
	handler := h.checkMetadataHeaders(http.HandlerFunc(h.computeMetadatav1ProjectProjectIDHandler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	err = verifyResponseHeaders(*rr.Result())
	if err != nil {
		t.Errorf("handler returned unexpected header: got %v", err)
	}

	if rr.Body.String() != expectedProjectID {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expectedProjectID)
	}
}

func TestAccessTokenHandler(t *testing.T) {
	expectedToken := "foo"
	expireInSeconds := 60
	h := &MetadataServer{
		Creds: &google.Credentials{
			ProjectID: "bar",
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: expectedToken,
				Expiry:      time.Now().Add(time.Second * time.Duration(expireInSeconds)),
				TokenType:   "Bearer",
			}),
		},
	}

	req, err := http.NewRequest(http.MethodGet, "/computeMetadata/v1/instance/service-accounts/{acct}/{key}", nil)
	if err != nil {
		t.Fatal(err)
	}

	addHeaders(*req)
	rr := httptest.NewRecorder()

	vars := map[string]string{
		"acct": "default",
		"key":  "token",
	}
	req = mux.SetURLVars(req, vars)

	handler := h.checkMetadataHeaders(http.HandlerFunc(h.getServiceAccountHandler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	err = verifyResponseHeaders(*rr.Result())
	if err != nil {
		t.Errorf("handler returned unexpected header: got %v", err)
	}

	resp := fmt.Sprintf("{\"access_token\":\"%s\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", expectedToken, expireInSeconds)
	if rr.Body.String() != resp {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), resp)
	}
}

func TestAccessTokenDefaultCredentialHandler(t *testing.T) {
	expectedToken := "foo"
	expireInSeconds := 60

	creds := &google.Credentials{
		ProjectID: "bar",
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: expectedToken,
			Expiry:      time.Now().Add(time.Second * time.Duration(expireInSeconds)),
			TokenType:   "Bearer",
		})}

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, creds, &Claims{})
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	// note default credentials here will attempt to use your actual token instead of the emulator value
	//  for this test to pass, run `gcloud auth application-default revoke` first
	ts, err := google.DefaultTokenSource(context.Background(), cloudPlatformScope)
	if err != nil {
		t.Errorf("error getting tokenSource %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}

	if tok.AccessToken != expectedToken {
		t.Errorf("handler returned unexpected body: got %v want %v", tok.AccessToken, expectedToken)
	}
}

func TestAccessTokenComputeCredentialHandler(t *testing.T) {
	expectedToken := "foo"
	expireInSeconds := 60

	creds := &google.Credentials{
		ProjectID: "bar",
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: expectedToken,
			Expiry:      time.Now().Add(time.Second * time.Duration(expireInSeconds)),
			TokenType:   "Bearer",
		})}

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, creds, &Claims{})
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	ts := google.ComputeTokenSource("default", cloudPlatformScope)
	if err != nil {
		t.Errorf("error getting tokenSource %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}

	if tok.AccessToken != expectedToken {
		t.Errorf("handler returned unexpected body: got %v want %v", tok.AccessToken, expectedToken)
	}
}

func TestAccessTokenEnvironmentCredentialHandler(t *testing.T) {
	expectedToken := "foo"

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	t.Setenv("GOOGLE_ACCESS_TOKEN", expectedToken)

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, &Claims{})
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	// note default credentials here will attempt to use your actual token instead of the emulator value
	//  for this test to pass, run `gcloud auth application-default revoke` first
	ts, err := google.DefaultTokenSource(context.Background(), cloudPlatformScope)
	if err != nil {
		t.Errorf("error getting tokenSource %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}

	if tok.AccessToken != expectedToken {
		t.Errorf("handler returned unexpected body: got %v want %v", tok.AccessToken, expectedToken)
	}
}

func TestOnGCEHandler(t *testing.T) {

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, &Claims{})
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	if !metadata.OnGCE() {
		t.Errorf("handler returned unexpected response expected got true")
	}
}

func TestProjectNumberHandler(t *testing.T) {
	expectedProjectNumber := int64(123456)
	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	cc := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Project: Project{
					NumericProjectID: expectedProjectNumber,
				},
			},
		},
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, cc)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	projectNumber, err := metadata.NumericProjectIDWithContext(context.Background())
	if err != nil {
		t.Errorf("error getting ProjectNumber: got %v", err)
	}

	if projectNumber != fmt.Sprintf("%d", expectedProjectNumber) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			fmt.Sprintf("%d", expectedProjectNumber), expectedProjectNumber)
	}
}

func TestInstanceIDHandler(t *testing.T) {
	expectedInstanceID := int64(123456)
	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	cc := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Instance: Instance{
					ID: expectedInstanceID,
				},
			},
		},
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, cc)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	mid, err := metadata.InstanceIDWithContext(context.Background())
	if err != nil {
		t.Errorf("error getting ProjectNumber: got %v", err)
	}

	if mid != fmt.Sprintf("%d", expectedInstanceID) {
		t.Errorf("handler returned unexpected body: got %s want %v",
			mid, expectedInstanceID)
	}
}

func TestMaintenanceEventWaitForChange(t *testing.T) {
	oldClaim := "NONE"
	newClaim := "MIGRATE_ON_HOST_MAINTENANCE"

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	cc := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Instance: Instance{
					MaintenanceEvent: oldClaim,
				},
			},
		},
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, cc)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}

	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	// change the value 2 seconds later, yes, i know its a race condition
	/// but 5 seconds is more than enough time to to make the outbound request
	/// outside of the go routine
	go func() {
		time.Sleep(2 * time.Second)
		h.Claims.ComputeMetadata.V1.Instance.MaintenanceEvent = newClaim
	}()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/computeMetadata/v1/instance/maintenance-event?wait_for_change=true", p), nil)
	if err != nil {
		t.Fatal(err)
	}

	addHeaders(*req)
	c := &http.Client{}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()
	mid, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(mid) != newClaim {
		t.Errorf("handler returned unexpected body: got %s want %v",
			mid, newClaim)
	}
}

func TestAttributeWaitForChange(t *testing.T) {
	mKey := "metadataKey1"
	valOrig := "originalValue"
	valNew := "newValue"

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	cc := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Instance: Instance{
					Attributes: map[string]string{
						mKey:  valOrig,
						"foo": "bar",
					},
				},
			},
		},
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	h, err := NewMetadataServer(context.Background(), sc, &google.Credentials{}, cc)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}

	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	go func() {
		time.Sleep(2 * time.Second)
		h.Claims.ComputeMetadata.V1.Instance.Attributes = map[string]string{mKey: valNew, "foo": "bar"}
	}()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/computeMetadata/v1/instance/attributes/%s?wait_for_change=true", p, mKey), nil)
	if err != nil {
		t.Fatal(err)
	}

	addHeaders(*req)
	c := &http.Client{}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()
	mid, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(mid) != valNew {
		t.Errorf("handler returned unexpected body: got %s want %v",
			mid, valNew)
	}
}

/*
# export CICD_SA_JSON=`cat certs/metadata-sa.json`
# export CICD_SA_PEM=`cat certs/metadata-sa.json | jq -r '.private_key'`
# export CICD_SA_EMAIL=`cat certs/metadata-sa.json | jq -r '.client_email'`
*/

func TestRealAccessToken(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	// saPEM := os.Getenv("CICD_SA_PEM")
	saJSON := os.Getenv("CICD_SA_JSON")

	creds, err := google.CredentialsFromJSON(t.Context(), []byte(saJSON), cloudPlatformScope)
	if err != nil {
		t.Errorf("error getting default creds %v", err)
	}

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	cl := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Project: Project{
					ProjectID: "testing",
				},
				Instance: Instance{
					ServiceAccounts: map[string]serviceAccountDetails{
						"default": serviceAccountDetails{
							Aliases: []string{"default"},
							Email:   saEmail,
							Scopes:  []string{cloudPlatformScope},
						},
					},
				},
			},
		},
	}

	h, err := NewMetadataServer(context.Background(), sc, creds, cl)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	ts := google.ComputeTokenSource("default", cloudPlatformScope)
	// ts, err := google.DefaultTokenSource(t.Context(), cloudPlatformScope)
	// if err != nil {
	// 	t.Errorf("error starting emulator %v", err)
	// }
	_, err = ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}
}

func TestRealIdToken(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	// saPEM := os.Getenv("CICD_SA_PEM")
	saJSON := os.Getenv("CICD_SA_JSON")

	creds, err := google.CredentialsFromJSON(t.Context(), []byte(saJSON), cloudPlatformScope)
	if err != nil {
		t.Errorf("error getting default creds %v", err)
	}

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port: fmt.Sprintf(":%d", p),
	}

	cl := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Project: Project{
					ProjectID: "testing",
				},
				Instance: Instance{
					ServiceAccounts: map[string]serviceAccountDetails{
						"default": serviceAccountDetails{
							Aliases: []string{"default"},
							Email:   saEmail,
							Scopes:  []string{cloudPlatformScope},
						},
					},
				},
			},
		},
	}

	h, err := NewMetadataServer(context.Background(), sc, creds, cl)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	aud := "https://foo.bar"
	ts, err := idtoken.NewTokenSource(t.Context(), aud)
	if err != nil {
		t.Errorf("error getting tokensource %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}
	pld, err := idtoken.Validate(t.Context(), tok.AccessToken, aud)
	if err != nil {
		t.Errorf("error validating id_token %v", err)
	}
	email, ok := pld.Claims["email"]
	if !ok {
		t.Errorf("id_token without email returned")
	}
	if email != saEmail {
		t.Errorf("id_token with incorrect email returned, expected %s, got %s", saEmail, email)
	}
}

// /*
// 	"github.com/google/go-tpm-tools/simulator"
// 	"github.com/google/go-tpm/tpm2"
// 	"github.com/google/go-tpm/tpm2/transport"
// 	saltpm "github.com/salrashid123/oauth2/v3"
// */

func loadKey(rwr transport.TPM, saPEM string, persistentHandle uint, keyFilePath string, keyPassword []byte) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	pv, ok := pvk.(*rsa.PrivateKey)
	if !ok {
		return 0, tpm2.TPM2BName{}, nil, fmt.Errorf("Private kew not rsa.PrivateKey")
	}

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(pv.PublicKey.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pv.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		AuthValue: tpm2.TPM2BAuth{
			Buffer: keyPassword,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: loadResponse.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)

		evictContextCmd := tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: tpm2.TPMIDHPersistent(persistentHandle),
				Name:   pub.Name,
			},
			PersistentHandle: tpm2.TPMIDHPersistent(persistentHandle),
		}
		_, err = evictContextCmd.Execute(rwr)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   pub.Name,
		},
		PersistentHandle: tpm2.TPMIDHPersistent(persistentHandle),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	tkf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHOwner,
		Pubkey:    tpm2.New2B(rsaTemplate),
		Privkey:   importResponse.OutPrivate,
	}
	b := new(bytes.Buffer)
	err = keyfile.Encode(b, tkf)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	err = os.WriteFile(keyFilePath, b.Bytes(), 0644)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return loadResponse.ObjectHandle, pub.Name, closer, nil
}

const swTPMPath = "127.0.0.1:2321"

func TestTPMAccessTokenCredentialHandler(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	if err != nil {
		t.Errorf("error getting simulator %v", err)
	}
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	tests := []struct {
		name             string
		keyPassword      []byte
		persistentHandle int
	}{
		{"noKeyPassword", nil, 0x81008001},
		{"withKeyPassword", []byte("mypass"), 0x81008001},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, _, closer, err := loadKey(rwr, saPEM, uint(tc.persistentHandle), filePath, tc.keyPassword)
			if err != nil {
				t.Errorf("error loading key %v", err)
			}
			defer closer()

			var authSession tpmjwt.Session
			if tc.keyPassword != nil {
				authSession, err = tpmjwt.NewPasswordAuthSession(rwr, tc.keyPassword, 0)
				if err != nil {
					t.Errorf("error creating password session %v", err)
				}
			}
			tpmts, err := saltpm.TpmTokenSource(&saltpm.TpmTokenConfig{
				TPMDevice:   tpmDevice,
				Handle:      k,
				AuthSession: authSession,
				Email:       saEmail,
				Scopes:      []string{cloudPlatformScope},
			})
			if err != nil {
				t.Errorf("error creating tokensource %v", err)
			}
			creds := &google.Credentials{
				ProjectID:   "bar",
				TokenSource: tpmts}

			p, err := getFreePort()
			if err != nil {
				t.Errorf("error getting emulator port %v", err)
			}
			sc := &ServerConfig{
				Port:   fmt.Sprintf(":%d", p),
				UseTPM: true,
				Handle: k,
			}

			cl := &Claims{
				ComputeMetadata: ComputeMetadata{
					V1: V1{
						Project: Project{
							ProjectID: "testing",
						},
						Instance: Instance{
							ServiceAccounts: map[string]serviceAccountDetails{
								"default": serviceAccountDetails{
									Aliases: []string{"default"},
									Email:   saEmail,
									Scopes:  []string{cloudPlatformScope},
								},
							},
						},
					},
				},
			}

			h, err := NewMetadataServer(context.Background(), sc, creds, cl)
			if err != nil {
				t.Errorf("error creating emulator %v", err)
			}
			err = h.Start()
			if err != nil {
				t.Errorf("error starting emulator %v", err)
			}
			defer h.Shutdown()

			t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

			ts, err := google.DefaultTokenSource(context.Background(), cloudPlatformScope)
			if err != nil {
				t.Errorf("error getting tokenSource %v", err)
			}

			_, err = ts.Token()
			if err != nil {
				t.Errorf("error getting token %v", err)
			}

			// ctx := context.Background()
			// storeageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
			// if err != nil {
			// 	t.Errorf("Unable to acquire storage Client: %v", err)
			// }

			// it := storeageClient.Buckets(ctx, "some-test-project")
			// for {
			// 	bucketAttrs, err := it.Next()
			// 	if err == iterator.Done {
			// 		break
			// 	}
			// 	if err != nil {
			// 		t.Errorf("Unable to acquire storage Client: %v", err)
			// 	}
			// 	t.Log(bucketAttrs.Name)
			// }
			closer()
		})
	}
}

func TestTPMIdTokenHandler(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	if err != nil {
		t.Errorf("error getting simulator %v", err)
	}
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008003
	k, _, closer, err := loadKey(rwr, saPEM, uint(persistentHandle), filePath, nil)
	if err != nil {
		t.Errorf("error loading key %v", err)
	}
	defer closer()

	var authSession tpmjwt.Session
	tpmts, err := saltpm.TpmTokenSource(&saltpm.TpmTokenConfig{
		TPMDevice:   tpmDevice,
		Handle:      k,
		AuthSession: authSession,
		Email:       saEmail,
		Scopes:      []string{cloudPlatformScope},
	})
	if err != nil {
		t.Errorf("error creating key %v", err)
	}
	creds := &google.Credentials{
		ProjectID:   "bar",
		TokenSource: tpmts}

	p, err := getFreePort()
	if err != nil {
		t.Errorf("error getting emulator port %v", err)
	}
	sc := &ServerConfig{
		Port:      fmt.Sprintf(":%d", p),
		TPMDevice: tpmDevice,
		UseTPM:    true,
		Handle:    k,
	}

	cl := &Claims{
		ComputeMetadata: ComputeMetadata{
			V1: V1{
				Project: Project{
					ProjectID: "testing",
				},
				Instance: Instance{
					ServiceAccounts: map[string]serviceAccountDetails{
						"default": serviceAccountDetails{
							Aliases: []string{"default"},
							Email:   saEmail,
							Scopes:  []string{cloudPlatformScope},
						},
					},
				},
			},
		},
	}

	h, err := NewMetadataServer(t.Context(), sc, creds, cl)
	if err != nil {
		t.Errorf("error creating emulator %v", err)
	}
	err = h.Start()
	if err != nil {
		t.Errorf("error starting emulator %v", err)
	}
	defer h.Shutdown()

	t.Setenv("GCE_METADATA_HOST", fmt.Sprintf("127.0.0.1:%d", p))

	aud := "https://foo.bar"
	ts, err := idtoken.NewTokenSource(t.Context(), aud)
	if err != nil {
		t.Errorf("error getting tokensource %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Errorf("error getting token %v", err)
	}
	pld, err := idtoken.Validate(t.Context(), tok.AccessToken, aud)
	if err != nil {
		t.Errorf("error validating id_token %v", err)
	}
	email, ok := pld.Claims["email"]
	if !ok {
		t.Errorf("id_token without email returned")
	}
	if email != saEmail {
		t.Errorf("id_token with incorrect email returned, expected %s, got %s", saEmail, email)
	}
}
