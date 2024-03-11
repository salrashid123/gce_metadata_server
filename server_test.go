package mds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"cloud.google.com/go/compute/metadata"
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

	projectNumber, err := metadata.NumericProjectID()
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

	mid, err := metadata.InstanceID()
	if err != nil {
		t.Errorf("error getting ProjectNumber: got %v", err)
	}

	if mid != fmt.Sprintf("%d", expectedInstanceID) {
		t.Errorf("handler returned unexpected body: got %s want %v",
			mid, expectedInstanceID)
	}
}
