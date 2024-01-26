package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func addHeaders(req http.Request) http.Request {
	req.Header.Set("Metadata-Flavor", "xGoogle")
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
		c: claims{
			ComputeMetadata: computeMetadata{
				V1: v1{
					Project: project{
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
		creds: &google.Credentials{
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
