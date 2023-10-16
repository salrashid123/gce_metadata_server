// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"
	"sync"

	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/glog"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"golang.org/x/net/http2"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"

	"golang.org/x/oauth2"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	iamcredentials "cloud.google.com/go/iam/credentials/apiv1"
	iamcredentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"
)

var (
	cfg         = &serverConfig{}
	hostHeaders = []string{"metadata", "metadata.google.internal", "169.254.169.254"}

	customAttributeMap = map[string]string{"k1": "v1", "k2": "v2"}

	tokenMutex = &sync.Mutex{}

	creds *google.Credentials

	instanceID, projectNumber int
)

const (
	emailScope         = "https://www.googleapis.com/auth/userinfo.email"
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	googleAccessToken  = "GOOGLE_ACCESS_TOKEN"
	googleIDToken      = "GOOGLE_ID_TOKEN"
)

type serverConfig struct {
	flInterface           string
	flPort                string
	flDomainSocket        string
	flnumericProjectID    string // should be an int
	fltokenScopes         string
	flprojectID           string
	flserviceAccountEmail string
	serviceAccountFile    string
	flImpersonate         bool
	flFederate            bool
	flZone                string
	flInstanceID          string // should be an int
	flInstanceName        string
	flHostName            string
	flTPM                 bool
	flTPMPath             string
	flPersistentHandle    int
}

// metadata server returns an "expires_in" while oauth2.Token returns Expiry time.time
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

	if isEnvironmentOverrideSet() {
		// access_token is opaque but you _can_ get the exp
		// time by calling  curl https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=
		// ...but i don't see it necessary to populate the expiration field, besides
		// https://godoc.org/golang.org/x/oauth2#Token
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{
				AccessToken: os.Getenv(googleAccessToken),
				Expiry:      time.Now().Add(time.Hour * 1),
				TokenType:   "Bearer",
			},
		)
		creds = &google.Credentials{
			ProjectID:   cfg.flprojectID,
			TokenSource: ts,
		}
	}
	if cfg.flTPM {
		// return a cached token
		if creds != nil {
			tok, err := creds.TokenSource.Token()
			if err != nil {
				glog.Error(err)
				return nil, err
			}

			if tok.Valid() {
				now := time.Now().UTC()
				diff := tok.Expiry.Sub(now)
				return &metadataToken{
					AccessToken: tok.AccessToken,
					ExpiresIn:   int(diff.Round(time.Second).Seconds()),
					TokenType:   tok.TokenType,
				}, nil
			}
		}

		rwc, err := tpm2.OpenTPM(cfg.flTPMPath)
		if err != nil {
			glog.Errorf("can't open TPM %s: %v", cfg.flTPMPath, err)
			return nil, err
		}
		defer rwc.Close()
		k, err := client.LoadCachedKey(rwc, tpmutil.Handle(cfg.flPersistentHandle), nil)
		if err != nil {
			glog.Errorf("ERROR:  could not initialize Key: %v", err)
			return nil, err
		}
		defer k.Close()
		// now we're ready to sign

		iat := time.Now()
		exp := iat.Add(time.Second * 10)

		type oauthJWT struct {
			jwt.RegisteredClaims
			Scope string `json:"scope"`
		}

		claims := &oauthJWT{
			jwt.RegisteredClaims{
				Issuer:    cfg.flserviceAccountEmail,
				Audience:  []string{"https://oauth2.googleapis.com/token"},
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
			},
			strings.Join(strings.Split(cfg.fltokenScopes, ","), " "),
		}

		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		ctx := context.Background()
		config := &tpmjwt.TPMConfig{
			TPMDevice: rwc,
			Key:       k,
		}

		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			glog.Errorf("Unable to initialize tpmJWT: %v", err)
			return nil, err
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			glog.Errorf("Error signing %v", err)
			return nil, err
		}

		client := &http.Client{}

		data := url.Values{}
		data.Set("grant_type", "assertion")
		data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			glog.Errorf("Error: Unable to generate token Request, %v\n", err)
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			glog.Errorf("Error: unable to POST token request, %v\n", err)
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			f, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error Reading response body, %v\n", err)
				return nil, err
			}
			glog.Errorf("Error: Token Request error:, %s\n", f)
			return nil, fmt.Errorf("Error response from oauth2 %s\n", f)
		}
		defer resp.Body.Close()
		var ret metadataToken
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			return nil, err
		}
		t := oauth2.Token{
			AccessToken: ret.AccessToken,
			Expiry:      time.Now().Add(time.Second * time.Duration(ret.ExpiresIn)),
			TokenType:   ret.TokenType,
		}
		creds = &google.Credentials{
			ProjectID:   cfg.flprojectID,
			TokenSource: oauth2.StaticTokenSource(&t),
		}
		return &ret, nil
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	now := time.Now().UTC()
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
	if isEnvironmentOverrideSet() {
		return os.Getenv(googleIDToken), nil
	}
	var idTokenSource oauth2.TokenSource
	var err error

	ctx := context.Background()
	if cfg.flImpersonate {

		idTokenSource, err = impersonate.IDTokenSource(ctx,
			impersonate.IDTokenConfig{
				TargetPrincipal: cfg.flserviceAccountEmail,
				Audience:        targetAudience,
				IncludeEmail:    true,
			},
		)
	} else if cfg.flFederate {

		c, err := iamcredentials.NewIamCredentialsClient(ctx)
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer c.Close()

		req := &iamcredentialspb.GenerateIdTokenRequest{
			Name:         fmt.Sprintf("projects/-/serviceAccounts/%s", cfg.flserviceAccountEmail),
			Audience:     targetAudience,
			IncludeEmail: true,
		}
		resp, err := c.GenerateIdToken(ctx, req)
		if err != nil {
			glog.Errorln(err)
			return "", fmt.Errorf("could not generateID Token %v", err)
		}

		idTokenSource = oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: resp.Token,
		})
	} else if cfg.flTPM {
		rwc, err := tpm2.OpenTPM(cfg.flTPMPath)
		if err != nil {
			glog.Errorf("can't open TPM %s: %v", cfg.flTPMPath, err)
			return "", err
		}
		defer rwc.Close()
		k, err := client.LoadCachedKey(rwc, tpmutil.Handle(cfg.flPersistentHandle), nil)
		if err != nil {
			glog.Errorf("ERROR:  could not initialize Key: %v", err)
			return "", err
		}
		defer k.Close()
		// now we're ready to sign

		iat := time.Now()
		exp := iat.Add(time.Second * 10)

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			jwt.RegisteredClaims{
				Issuer:    cfg.flserviceAccountEmail,
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
			targetAudience,
		}

		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		ctx := context.Background()
		config := &tpmjwt.TPMConfig{
			TPMDevice: rwc,
			Key:       k,
		}

		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			glog.Errorf("Unable to initialize tpmJWT: %v", err)
			return "", err
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			glog.Errorf("Error signing %v", err)
			return "", err
		}

		client := &http.Client{}

		data := url.Values{}
		data.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			glog.Errorf("Error: Unable to generate token Request, %v\n", err)
			return "", err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			glog.Errorf("Error: unable to POST token request, %v\n", err)
			return "", err
		}

		if resp.StatusCode != http.StatusOK {
			f, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error Reading response body, %v\n", err)
				return "", err
			}
			glog.Errorf("Error: Token Request error:, %s\n", f)
			return "", fmt.Errorf("Error response from oauth2 %s\n", f)
		}
		defer resp.Body.Close()

		type idTokenResponse struct {
			IdToken string `json:"id_token"`
		}

		var ret idTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			return "", err
		}
		return ret.IdToken, nil
	} else {
		idTokenSource, err = idtoken.NewTokenSource(ctx, targetAudience, idtoken.WithCredentialsJSON(creds.JSON))
		if err != nil {
			glog.Errorf("Error getting tokenSource %v\n")
			return "", fmt.Errorf("could not get id_token %v", err)
		}
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
	if os.Getenv("GOOGLE_PROJECT_ID") != "" {
		return os.Getenv("GOOGLE_PROJECT_ID")
	}
	return creds.ProjectID
}

func getNumericProjectID() string {
	if cfg.flnumericProjectID != "" {
		return cfg.flnumericProjectID
	}
	if os.Getenv("GOOGLE_NUMERIC_PROJECT_ID") != "" {
		return os.Getenv("GOOGLE_NUMERIC_PROJECT_ID")
	}
	return cfg.flnumericProjectID
}

func getServiceAccountEmail() string {
	if cfg.flserviceAccountEmail != "" {
		return cfg.flserviceAccountEmail
	}
	if os.Getenv("GOOGLE_ACCOUNT_EMAIL") != "" {
		return os.Getenv("GOOGLE_ACCOUNT_EMAIL")
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

		glog.V(10).Infof("Got Request: path[%s] query[%s]", r.URL.Path, r.URL.RawQuery)

		if r.URL.Query().Has("recursive") {
			if strings.ToLower(r.URL.Query().Get("recursive")) == "true" {
				glog.V(10).Infof("WARNING: ?recursive=true has limited depth support; check handler implementation")
			}
		}
		w.Header().Add("Server", "Metadata Server for VM")
		w.Header().Add("Metadata-Flavor", "Google")
		w.Header().Add("X-XSS-Protection", "0")
		w.Header().Add("X-Frame-Options", "0")

		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}

		flavor := r.Header.Get("Metadata-Flavor")
		if flavor == "" && r.RequestURI != "/" {
			http.Error(w, "Missing required header \"Metadata-Flavor\": \"Google\"", http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "ok")
}

func projectIDHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, getProjectID())
}

func numericProjectIDHandler(w http.ResponseWriter, r *http.Request) {
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
	// TODO: its possible the vm doens't have a svc-account
	w.Header().Add("Content-Type", "application/text")
	fmt.Fprint(w, "default/\n"+getServiceAccountEmail()+"/\n")
}

func instanceRedirectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	http.Redirect(w, r, "/computeMetadata/v1/instance/", 302)
}

func instanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/text")
	vals := []string{"attributes/", "cpu-platform", "description",
		"disks/", "guest-attributes/", "hostname", "id", "image",
		"legacy-endpoint-access/", "licenses/", "machine-type",
		"maintenance-event", "name", "network-interfaces/",
		"preempted", "remaining-cpu-time", "scheduling/",
		"service-accounts/", "tags", "virtual-clock/", "zone"}
	resp := ""
	for _, v := range vals {
		resp = resp + v + "\n"
	}
	fmt.Fprint(w, resp)
}

func projectRootRedirectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	http.Redirect(w, r, "/computeMetadata/v1/project/", 302)
}

func projectRootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/text")
	vals := []string{"attributes/", "numeric-project-id", "project-id"}
	resp := ""
	for _, v := range vals {
		resp = resp + v + "\n"
	}
	fmt.Fprint(w, resp)
}

func instancev1RedirectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	http.Redirect(w, r, "/computeMetadata/v1/", 301)
}

func instancev1Handler(w http.ResponseWriter, r *http.Request) {
	// account for limited ?recursive=true
	if r.URL.Query().Has("recursive") {
		if strings.ToLower(r.URL.Query().Get("recursive")) == "true" {
			// for now, we're just going to return projectID, zone and an instanceid
			// InstanceV1Metadata is used to emit recursive data back
			// for /computeMetadata/v1/?recursive=true
			type instanceMeta struct {
				Zone         string `json:"zone,omitempty"`
				InstanceName string `json:"name,omitempty"`
				InstanceID   uint64 `json:"id,int,omitempty"`
				Hostname     string `json:"hostname,int,omitempty"`
			}
			type projectMeta struct {
				ProjectID     string `json:"projectId,omitempty"`
				ProjectNumber uint64 `json:"numericProjectId,int,omitempty"`
			}
			type instanceV1Metadata struct {
				Instance *instanceMeta `json:"instance,string,omitempty"`
				Project  *projectMeta  `json:"project,string,omitempty"`
			}

			w.Header().Add("Content-Type", "application/json")

			resp := &instanceV1Metadata{
				Instance: &instanceMeta{
					InstanceName: cfg.flInstanceName,
					InstanceID:   uint64(instanceID),
					Hostname:     cfg.flHostName,
					Zone:         fmt.Sprintf("projects/%d/zones/%s", projectNumber, cfg.flZone),
				},
				Project: &projectMeta{
					ProjectNumber: uint64(projectNumber),
					ProjectID:     cfg.flprojectID,
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
	}
	w.Header().Add("Content-Type", "application/text")
	vals := []string{"instance/", "oslogin/", "project/"}
	resp := ""
	for _, v := range vals {
		resp = resp + v + "\n"
	}
	fmt.Fprint(w, resp)
}

func instancev1PathHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	glog.Infof("/computeMetadata/v1/instance/{key} called for key %s", vars["key"])

	switch vars["key"] {
	case "id":
		if cfg.flInstanceID != "" {
			fmt.Fprint(w, cfg.flInstanceID)
		} else if os.Getenv("GOOGLE_INSTANCE_ID") != "" {
			fmt.Fprint(w, os.Getenv("GOOGLE_INSTANCE_ID"))
		} else {
			http.Error(w, "value_not_set", http.StatusNotFound)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}
	case "name":
		if cfg.flInstanceName != "" {
			fmt.Fprint(w, cfg.flInstanceName)
		} else if os.Getenv("GOOGLE_INSTANCE_NAME") != "" {
			fmt.Fprint(w, os.Getenv("GOOGLE_INSTANCE_NAME"))
		} else {
			http.Error(w, "value_not_set", http.StatusNotFound)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}
	case "hostname":
		if cfg.flHostName != "" {
			fmt.Fprint(w, cfg.flHostName)
		} else if os.Getenv("GOOGLE_INSTANCE_HOSTNAME") != "" {
			fmt.Fprint(w, os.Getenv("GOOGLE_INSTANCE_HOSTNAME"))
		} else {
			http.Error(w, "value_not_set", http.StatusNotFound)
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			return
		}
	default:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")
	return
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
		w.Header().Set("Content-Type", "application/text")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)

}

func notFound(w http.ResponseWriter, r *http.Request) {
	glog.Infof("%s called but is not implemented", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
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
			glog.Errorf("Error getting Token %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/text")
			return
		}
		js, err := json.Marshal(tok)
		if err != nil {
			glog.Errorf("Error unmarshalling Token %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/text")
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

func isEnvironmentOverrideSet() bool {
	if os.Getenv(googleAccessToken) != "" && os.Getenv(googleIDToken) != "" {
		return true
	}
	return false
}

func main() {
	ctx := context.Background()
	flag.StringVar(&cfg.flInterface, "interface", "127.0.0.1", "interface address to bind to")
	flag.StringVar(&cfg.flPort, "port", ":8080", "port...")
	flag.StringVar(&cfg.flDomainSocket, "domainsocket", "", "listen only on unix socket")
	flag.StringVar(&cfg.flnumericProjectID, "numericProjectId", "", "numericProjectId...")
	flag.StringVar(&cfg.fltokenScopes, "tokenScopes", fmt.Sprintf("%s,%s", emailScope, cloudPlatformScope), "tokenScopes")
	flag.StringVar(&cfg.flprojectID, "projectId", "", "projectId...")
	flag.StringVar(&cfg.flserviceAccountEmail, "serviceAccountEmail", "", "serviceAccountEmail...")
	flag.StringVar(&cfg.serviceAccountFile, "serviceAccountFile", "", "serviceAccountFile...")
	flag.BoolVar(&cfg.flImpersonate, "impersonate", false, "Impersonate a service Account instead of using the keyfile")
	flag.BoolVar(&cfg.flFederate, "federate", false, "Use Workload Identity Federation ADC")
	flag.StringVar(&cfg.flZone, "zone", "", "zone where any instance runs")
	flag.StringVar(&cfg.flInstanceID, "instanceID", "", "instance id for a vm")
	flag.StringVar(&cfg.flInstanceName, "instanceName", "", "instance name for a vm")
	flag.StringVar(&cfg.flHostName, "hostName", "", "instance host name for a vm")
	flag.BoolVar(&cfg.flTPM, "tpm", false, "Use TPM to get access and id_token")
	flag.StringVar(&cfg.flTPMPath, "tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	flag.IntVar(&cfg.flPersistentHandle, "persistentHandle", 0x81008000, "Handle value")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		flag.PrintDefaults()
		glog.Errorf("Invalid Argument error: "+s, v...)
		os.Exit(-1)
	}

	glog.Infof("Starting GCP metadataserver")

	r := mux.NewRouter()
	r.StrictSlash(false)

	r.Handle("/computeMetadata/v1/project", http.HandlerFunc(projectRootRedirectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/", http.HandlerFunc(projectRootHandler)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/project/project-id", http.HandlerFunc(projectIDHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/numeric-project-id", http.HandlerFunc(numericProjectIDHandler)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/project/attributes/{key}", http.HandlerFunc(attributesHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/", http.HandlerFunc(listServiceAccountHandler)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance", http.HandlerFunc(instanceRedirectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/", http.HandlerFunc(instanceHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/{key}", http.HandlerFunc(instancev1PathHandler)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1", http.HandlerFunc(instancev1RedirectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/", http.HandlerFunc(instancev1Handler)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}", http.HandlerFunc(getServiceAccountHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/", http.HandlerFunc(getServiceAccountIndexHandler)).Methods(http.MethodGet)
	r.Handle("/", http.HandlerFunc(rootHandler)).Methods(http.MethodGet)

	r.NotFoundHandler = http.HandlerFunc(notFound)
	http.Handle("/", checkMetadataHeaders(r))

	var l net.Listener
	var err error
	if cfg.flDomainSocket != "" {
		glog.Infof("domain socket specified, ignoring TCP listers, %s", cfg.flDomainSocket)
		l, err = net.Listen("unix", cfg.flDomainSocket)
		if err != nil {
			glog.Errorf("Error listening to domain socket: %v\n", err)
			os.Exit(-1)
		}
	} else {
		glog.Infof("tcp socket specified %s", fmt.Sprintf("%s%s", cfg.flInterface, cfg.flPort))
		l, err = net.Listen("tcp", fmt.Sprintf("%s%s", cfg.flInterface, cfg.flPort))
		if err != nil {
			glog.Errorf("Error listening to tcp socket: %v\n", err)
			os.Exit(-1)
		}
	}
	defer l.Close()

	srv := &http.Server{}
	http2.ConfigureServer(srv, &http2.Server{})

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// First check if env-var based overrides are set.  We need all of them to be set for the
	// client libraries.  We are _not_ going to set a credential object here but read it on request.
	// TODO: make the credential and runtime source data an adapter: eg, token, projectiD, etc
	//       gets read in from a variety of sources (args+svcAccountFile, env vars, kubernetes secrets)
	// serviceAccountFile based credentials isn't necessary if env-var based settings are used.
	// technically, you could mix and match env var and svc-account values but that makes it
	// pretty confusing...so I'll just go w/ one or the other

	if isEnvironmentOverrideSet() {
		glog.Infoln("Using environment variables for access and id_tokens")
	} else if cfg.flImpersonate {
		glog.Infoln("Using Service Account Impersonation")

		if cfg.flnumericProjectID == "" || cfg.flprojectID == "" || cfg.flserviceAccountEmail == "" {
			argError("projectId,numericProjectId,serviceAccountEmail must be set if impersonation is used")
		}

		var err error
		s := strings.Split(cfg.fltokenScopes, ",")
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: cfg.flserviceAccountEmail,
			Scopes:          s,
		})
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			os.Exit(1)
		}

		creds = &google.Credentials{
			ProjectID:   cfg.flprojectID,
			TokenSource: ts,
		}
	} else if cfg.flFederate {
		glog.Infoln("Using Workload Identity Federation")

		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			glog.Error("GOOGLE_APPLICATION_CREDENTIALSh --federate")
			os.Exit(1)
		}
		if cfg.flserviceAccountEmail == "" || cfg.flprojectID == "" || cfg.flnumericProjectID == "" {
			glog.Error("--serviceAccountEmail, projectId and numericProjectID must be specified with --federate")
			os.Exit(1)
		}

		glog.Infof("Federation path: %s", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		var err error
		creds, err = google.FindDefaultCredentials(ctx, strings.Split(cfg.fltokenScopes, ",")...)
		if err != nil {
			glog.Errorf("Unable load federated credentials %v", err)
			os.Exit(1)
		}
	} else if cfg.flTPM {
		glog.Infoln("Using TPM based token handle")

		if cfg.flPersistentHandle == 0 {
			glog.Error("persistent handle must be specified TPM")
			os.Exit(1)
		}
		// verify we actually have access to the TPM
		rwc, err := tpm2.OpenTPM(cfg.flTPMPath)
		if err != nil {
			glog.Errorf("can't open TPM %s: %v", cfg.flTPM, err)
			os.Exit(1)
		}
		err = rwc.Close()
		if err != nil {
			glog.Errorf("can't closing TPM %s: %v", cfg.flTPM, err)
			os.Exit(1)
		}
	} else {

		if cfg.serviceAccountFile == "" {
			argError("Either environment variable overides or -serviceAccountFile must be specified")
		}

		glog.Infoln("Using serviceAccountFile for credentials")
		var err error
		//creds, err = google.FindDefaultCredentials(ctx, tokenScopes)
		data, err := ioutil.ReadFile(cfg.serviceAccountFile)
		if err != nil {
			glog.Errorf("Unable to read serviceAccountFile %v", err)
			os.Exit(1)
		}
		s := strings.Split(cfg.fltokenScopes, ",")
		creds, err = google.CredentialsFromJSON(ctx, data, s...)
		if err != nil {
			glog.Errorf("Unable to parse serviceAccountFile %v ", err)
			os.Exit(1)
		}
	}

	if cfg.flInstanceID != "" {
		instanceID, err = strconv.Atoi(cfg.flInstanceID)
		if err != nil {
			glog.Errorf("Unable to convert instanceID to int %v ", err)
			os.Exit(1)
		}
	}
	if cfg.flnumericProjectID != "" {
		projectNumber, err = strconv.Atoi(cfg.flnumericProjectID)
		if err != nil {
			glog.Errorf("Unable to convert projectNumber to int %v ", err)
			os.Exit(1)
		}
	}

	go func() {
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
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
