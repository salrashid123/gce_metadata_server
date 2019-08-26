// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"encoding/json"
	"sync"

	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"

	"golang.org/x/net/http2"

	sal "github.com/salrashid123/oauth2/google"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"
)

var (
	cfg         = &serverConfig{}
	hostHeaders = []string{"metadata", "metadata.google.internal", "169.254.169.254"}

	customAttributeMap = map[string]string{"k1": "v1", "k2": "v2"}

	tokenMutex = &sync.Mutex{}

	creds *google.Credentials
)

const (
	emailScope = "https://www.googleapis.com/auth/userinfo.email"
)

type serverConfig struct {
	flPort                string
	flnumericProjectID    string
	fltokenScopes         string
	flprojectID           string
	flserviceAccountEmail string
	flserviAccountFile    string
}

type metadataToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type serviceAccountDetails struct {
	Aliases string `json:"aliases"`
	Email   string `json:"email"`
	Scopes  string `json:"scopes"`
}

func getAccessToken() (*metadataToken, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	tok, err := creds.TokenSource.Token()
	if err != nil {
		return &metadataToken{}, err
	}

	loc, _ := time.LoadLocation("UTC")
	now := time.Now().In(loc)
	diff := tok.Expiry.Sub(now)
	return &metadataToken{
		AccessToken: tok.AccessToken,
		ExpiresIn:   int(diff.Round(time.Second).Seconds()),
		TokenType:   tok.TokenType,
	}, nil

}

func getIDToken(targetAudience string) (string, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	idTokenSource, err := sal.IdTokenSource(
		sal.IdTokenConfig{
			Credentials: creds,
			Audiences:   []string{targetAudience},
		},
	)
	if err != nil {
		return "", err
	}
	tok, err := idTokenSource.Token()
	if err != nil {
		glog.Error(err)
		return "", err
	}
	return tok.AccessToken, nil
}

func getProjectID() string {
	if cfg.flprojectID != "" {
		return cfg.flprojectID
	}
	return creds.ProjectID
}

func getNumericProjectID() string {
	return cfg.flnumericProjectID
}

func getServiceAccountEmail() string {
	if cfg.flserviceAccountEmail != "" {
		return cfg.flserviceAccountEmail
	}
	conf, err := google.JWTConfigFromJSON(creds.JSON, emailScope)
	if err != nil {
		glog.Errorf("unable to get serviceAccountEmail from JSON certificate file %v", err)
		os.Exit(1)
	}
	return conf.Email
}

func checkMetadataHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		glog.V(10).Infof("Got Request: %v", r)
		w.Header().Add("Server", "Metadata Server for VM")
		w.Header().Add("Metadata-Flavor", "Google")
		w.Header().Add("X-XSS-Protection", "0")
		w.Header().Add("X-Frame-Options", "0")

		hasHostHeader := false
		for _, a := range hostHeaders {
			if a == r.Host {
				hasHostHeader = true
			}
		}

		if !hasHostHeader {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}
		flavor := r.Header.Get("Metadata-Flavor")
		if flavor == "" && r.RequestURI != "/" {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infoln("/ called")

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "ok")
}

func projectIDHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infoln("/computeMetadata/v1/project/project-id called")
	fmt.Fprint(w, getProjectID())
}

func numericProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infoln("/computeMetadata/v1/project/numeric-project-id called")
	fmt.Fprint(w, getNumericProjectID())
}

func attributesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	glog.Infof("/computeMetadata/v1/project/attributes/{k} called for attribute %v", vars["key"])

	if val, ok := customAttributeMap[vars["key"]]; ok {
		fmt.Fprint(w, val)
	} else {
		fmt.Fprint(w, http.StatusNotFound)
	}
}

func listServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infoln("/computeMetadata/v1/instance/service-accounts/ called")
	// TODO: its possible the vm doens't have a svc-account
	w.Header().Add("Content-Type", "application/text")
	fmt.Fprint(w, "default/\n"+getServiceAccountEmail()+"/\n")
}

func getServiceAccountIndexHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	glog.Infof("/computeMetadata/v1/instance/service-accounts/%v/ called", vars["acct"])
	// TODO: its possible the vm doens't have a svc-account

	var scopes string
	for _, e := range strings.Split(cfg.fltokenScopes, ",") {
		scopes = scopes + e + "\n"
	}

	js, err := json.Marshal(&serviceAccountDetails{
		Aliases: vars["acct"],
		Email:   getServiceAccountEmail(),
		Scopes:  scopes,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		w.Header().Set("Content-Type", "applicaiton/text")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)

}

func getServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	glog.Infof("/computeMetadata/v1/instance/service-accounts/%v/%v called", vars["acct"], vars["key"])

	switch vars["key"] {

	case "aliases":
		w.Header().Set("Content-Type", "application/text")
		fmt.Fprint(w, "default")

	case "email":
		w.Header().Set("Content-Type", "application/text")
		fmt.Fprint(w, getServiceAccountEmail())

	case "identity":
		k, ok := r.URL.Query()["audience"]
		if !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "non-empty audience parameter required")
			return
		}
		idtok, err := getIDToken(k[0])
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "text/html")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, idtok)

	case "scopes":

		var scopes string
		for _, e := range strings.Split(cfg.fltokenScopes, ",") {
			scopes = scopes + e + "\n"
		}
		w.Header().Set("Content-Type", "application/text")
		fmt.Fprint(w, scopes)

	case "token":
		tok, err := getAccessToken()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "applicaiton/text")
			return
		}
		js, err := json.Marshal(tok)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "applicaiton/text")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)

	default:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return
	}

}

func main() {
	ctx := context.Background()
	flag.StringVar(&cfg.flPort, "port", ":8080", "port...")
	flag.StringVar(&cfg.flnumericProjectID, "numericProjectId", "", "numericProjectId...")
	flag.StringVar(&cfg.fltokenScopes, "tokenScopes", "https://www.googleapis.com/auth/userinfo.email", "tokenScopes")
	flag.StringVar(&cfg.flprojectID, "projectId", "", "projectId...")
	flag.StringVar(&cfg.flserviceAccountEmail, "serviceAccountEmail", "", "serviceAccountEmail...")
	flag.StringVar(&cfg.flserviAccountFile, "serviceAccountFile", "", "serviceAccountFile...")
	flag.Parse()

	argError := func(s string, v ...interface{}) {
		flag.PrintDefaults()
		glog.Errorf("Invalid Argument error: "+s, v...)
		os.Exit(-1)
	}

	if cfg.flserviAccountFile == "" {
		argError("-serviceAccountFile must be specified")
	}

	glog.Infof("Starting GCP metadataserver on port, %v", cfg.flPort)

	r := mux.NewRouter()
	r.Handle("/computeMetadata/v1/project/project-id", checkMetadataHeaders(http.HandlerFunc(projectIDHandler))).Methods("GET")
	r.Handle("/computeMetadata/v1/project/numeric-project-id", checkMetadataHeaders(http.HandlerFunc(numericProjectIDHandler)))
	r.Handle("/computeMetadata/v1/project/attributes/{key}", checkMetadataHeaders(http.HandlerFunc(attributesHandler)))
	r.Handle("/computeMetadata/v1/instance/service-accounts/", checkMetadataHeaders(http.HandlerFunc(listServiceAccountHandler)))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/", checkMetadataHeaders(http.HandlerFunc(getServiceAccountIndexHandler)))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}", checkMetadataHeaders(http.HandlerFunc(getServiceAccountHandler)))
	r.Handle("/", checkMetadataHeaders(http.HandlerFunc(rootHandler)))
	//r.Handle("/", checkMetadataHeaders(http.FileServer(http.Dir("./static"))))
	http.Handle("/", r)

	srv := &http.Server{
		Addr: cfg.flPort,
	}
	http2.ConfigureServer(srv, &http2.Server{})

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	var err error
	//creds, err = google.FindDefaultCredentials(ctx, tokenScopes)
	data, err := ioutil.ReadFile(cfg.flserviAccountFile)
	if err != nil {
		glog.Errorf("Unalbe to read serviceAccountFile %v", err)
		os.Exit(1)
	}
	s := strings.Split(cfg.fltokenScopes, ",")
	creds, err = google.CredentialsFromJSON(ctx, data, s...)
	if err != nil {
		glog.Errorf("Unalbe to parse serviceAccountFile %v ", err)
		os.Exit(1)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			glog.Fatalf("listen: %s\n", err)
		}
	}()
	glog.Infoln("Server Started")
	<-done
	glog.Infoln("Server Stopped")

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	glog.Infoln("Server Exited Properly")

}
