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
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"context"
	"flag"
	"fmt"

	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/glog"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"golang.org/x/net/http2"
	"golang.org/x/oauth2"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	iamcredentials "cloud.google.com/go/iam/credentials/apiv1"
	iamcredentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
)

type MetadataServer struct {
	tokenMutex sync.Mutex
	creds      *google.Credentials
	c          claims
	cfg        serverConfig
}

var (
	hostHeaders = []string{"metadata", "metadata.google.internal", "169.254.169.254"}
)

const (
	emailScope                = "https://www.googleapis.com/auth/userinfo.email"
	cloudPlatformScope        = "https://www.googleapis.com/auth/cloud-platform"
	googleAccessToken         = "GOOGLE_ACCESS_TOKEN"
	googleIDToken             = "GOOGLE_ID_TOKEN"
	googleProjectID           = "GOOGLE_PROJECT_ID"
	googleProjectNumber       = "GOOGLE_NUMERIC_PROJECT_ID"
	googleServiceAccountEmail = "GOOGLE_SERVICE_ACCOUNT"

	metadata404Body = `
<!DOCTYPE html>
<html lang=en>
	<meta charset=utf-8>
	<meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
	<title>Error 404 (Not Found)!!1</title>
	<style>
		*{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
	</style>
	<a href=//www.google.com/><span id=logo aria-label=Google></span></a>
	<p><b>404.</b> <ins>That’s an error.</ins>
	<p>The requested URL <code>/computeMetadata/v1/project/attributes/ssh-keysd</code> was not found on this server.  <ins>That’s all we know.</ins>
`
)

type serverConfig struct {
	flInterface    string
	flPort         string
	flDomainSocket string

	flConfigFile string

	serviceAccountFile string

	flImpersonate bool
	flFederate    bool

	flTPM              bool
	flTPMPath          string
	flPersistentHandle int
}

func httpError(w http.ResponseWriter, error string, code int, contentType string) {
	if contentType == "" {
		contentType = "text/html; charset=UTF-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

// metadata server returns an "expires_in" while oauth2.Token returns Expiry time.time
type metadataToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type serviceAccountDetails struct {
	Aliases  []string `json:"aliases" altjson:"aliases"`
	Email    string   `json:"email" altjson:"email"`
	Identity string   `json:"identity" altjson:"identity"`
	Scopes   []string `json:"scopes" altjson:"scopes"`
	Token    string   `json:"token" altjson:"token"`
}

type claims struct {
	ComputeMetadata computeMetadata `json:"computeMetadata"  altjson:"computeMetadata"`
}
type computeMetadata struct {
	V1 v1 `json:"v1" altjson:"v1"`
}
type v1 struct {
	Instance instance `json:"instance" altjson:"instance"`
	Oslogin  oslogin  `json:"oslogin"  altjson:"oslogin"`
	Project  project  `json:"project"  altjson:"project"`
}

type instance struct {
	Attributes  map[string]string `json:"attributes"  altjson:"attributes"`
	CPUPlatform string            `json:"cpuPlatform"  altjson:"cpu-platform"`
	Description string            `json:"description"  altjson:"description"`
	Disks       []struct {
		DeviceName string `json:"deviceName"  altjson:"device-name"`
		Index      int    `json:"index"  altjson:"index"`
		Interface  string `json:"interface"  altjson:"interface"`
		Mode       string `json:"mode"  altjson:"mode"`
		Type       string `json:"type"  altjson:"type"`
	} `json:"disks"  altjson:"disks"`
	GuestAttributes struct {
	} `json:"guestAttributes"  altjson:"guest-attributes"` // Guest attributes endpoint access is disabled.
	Hostname string `json:"hostname"  altjson:"hostname"`
	ID       int64  `json:"id"  altjson:"id"`
	Image    string `json:"image"  altjson:"image"`
	Licenses []struct {
		ID string `json:"id"  altjson:"id"`
	} `json:"licenses" altjson:"licenses"`
	MachineType       string `json:"machineType" altjson:"machine-type"`
	MaintenanceEvent  string `json:"maintenanceEvent" altjson:"maintenence-event"`
	Name              string `json:"name" altjson:"name"`
	NetworkInterfaces []struct {
		AccessConfigs []struct {
			ExternalIP string `json:"externalIp" altjson:"external-ip"`
			Type       string `json:"type" altjson:"type"`
		} `json:"accessConfigs" altjson:"access-configs"`
		DNSServers        []string `json:"dnsServers" altjson:"dns-servers"`
		ForwardedIps      []string `json:"forwardedIps" altjson:"forwarded-ips"`
		Gateway           string   `json:"gateway" altjson:"gateway"`
		IP                string   `json:"ip" altjson:"ip"`
		IPAliases         []string `json:"ipAliases" altjson:"ip-aliases"`
		Mac               string   `json:"mac" altjson:"mac"`
		Mtu               int      `json:"mtu" altjson:"mtu"`
		Network           string   `json:"network" altjson:"network"`
		Subnetmask        string   `json:"subnetmask" altjson:"subnetmask"`
		TargetInstanceIps []string `json:"targetInstanceIps" altjson:"target-instance-ips"`
	} `json:"networkInterfaces" altjson:"network-interfaces"`
	PartnerAttributes struct {
	} `json:"partnerAttributes" altjson:"partner-attributes"`
	Preempted        string `json:"preempted"  altjson:"preempted"`
	RemainingCPUTime int    `json:"remainingCpuTime" altjson:"remaining-cpu-time"`
	Scheduling       struct {
		AutomaticRestart  string `json:"automaticRestart" altjson:"automatic-restart"`
		OnHostMaintenance string `json:"onHostMaintenance" altjson:"on-host-maintenence"`
		Preemptible       string `json:"preemptible" altjson:"preemptible"`
	} `json:"scheduling" altjson:"scheduling"`
	ServiceAccounts map[string]serviceAccountDetails `json:"serviceAccounts" altjson:"service-accounts"`
	Tags            []string                         `json:"tags" altjson:"tags"`
	VirtualClock    struct {
		DriftToken string `json:"driftToken" altjson:"drift-token"`
	} `json:"virtualClock" altjson:"virtual-clock"`
	Zone string `json:"zone" altjson:"zone"`
}

type oslogin struct {
	Authenticate struct {
		Sessions struct {
		} `json:"sessions" altjson:"sessions"`
	} `json:"authenticate" altjson:"authenticate"`
}

type project struct {
	Attributes       map[string]string `json:"attributes" altjson:"attributes"`
	NumericProjectID int64             `json:"numericProjectId" altjson:"numeric-project-id"`
	ProjectID        string            `json:"projectId" altjson:"project-id"`
}

func (h *MetadataServer) checkMetadataHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		glog.V(10).Infof("Got Request: path[%s] query[%s]", r.URL.Path, r.URL.RawQuery)

		if r.URL.Query().Has("recursive") {
			if strings.ToLower(r.URL.Query().Get("recursive")) == "true" {
				glog.Warning("WARNING: ?recursive=true has limited depth support; check handler implementation")
			}
		}
		if r.URL.Query().Has("alt") {
			glog.Warning("WARNING: ?alt=text|json has limited support; check handler implementation")
		}

		w.Header().Add("Server", "Metadata Server for VM")
		w.Header().Add("Metadata-Flavor", "Google")
		w.Header().Add("X-XSS-Protection", "0")
		w.Header().Add("X-Frame-Options", "SAMEORIGIN")

		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			httpError(w, http.StatusText(http.StatusForbidden), http.StatusForbidden, "text/html; charset=UTF-8")
			return
		}

		flavor := r.Header.Get("Metadata-Flavor")
		glog.Infof("%s flavor", flavor)
		if flavor == "" && r.RequestURI != "/" {
			httpError(w, "Missing required header \"Metadata-Flavor\": \"Google\"", http.StatusForbidden, "text/html; charset=UTF-8")
			return
		}
		if flavor != "Google"  && r.RequestURI != "/" {
			h.notFound(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *MetadataServer) pathListFields(b interface{}) string {
	val := reflect.ValueOf(b)
	var resp string
	for i := 0; i < val.Type().NumField(); i++ {
		if val.Type().Field(i).Type.Kind() == reflect.Int64 || val.Type().Field(i).Type.Kind() == reflect.String || val.Type().Field(i).Type.Kind() == reflect.Int {
			resp = resp + val.Type().Field(i).Tag.Get("altjson") + "\n"
		} else {
			resp = resp + val.Type().Field(i).Tag.Get("altjson") + "/\n"
		}
	}
	return resp
}

func (h *MetadataServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.c)
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) notFound(w http.ResponseWriter, r *http.Request) {
	glog.Infof("%s called but is not implemented", r.URL.Path)
	httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
}

func (h *MetadataServer) computeMetadataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.c.ComputeMetadata)
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1Handler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1) {
		return
	}
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.c.ComputeMetadata.V1)
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1ProjectHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Project) {
		return
	}
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.c.ComputeMetadata.V1.Project)
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1ProjectProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	if os.Getenv(googleProjectID) != "" {
		fmt.Fprint(w, os.Getenv(googleProjectID))

	} else {
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Project.ProjectID)
	}
}

func (h *MetadataServer) computeMetadatav1ProjectNumericProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	if os.Getenv(googleProjectNumber) != "" {
		fmt.Fprint(w, os.Getenv(googleProjectNumber))
	} else {
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Project.NumericProjectID)
	}
}

func (h *MetadataServer) handleRecursion(w http.ResponseWriter, r *http.Request, s interface{}) bool {
	if r.URL.Query().Has("recursive") {
		if strings.ToLower(r.URL.Query().Get("recursive")) == "true" {
			jsonResponse, err := json.Marshal(s)
			if err != nil {
				glog.Errorf("Error marshalling json: %v\n", err)
				httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "text/html; charset=UTF-8")
				return true
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(jsonResponse)
			return true
		}
	}
	return false
}

func (h *MetadataServer) handleBasePathRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", fmt.Sprintf("http://%s%s/", r.Host, r.RequestURI))
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusMovedPermanently)
	fmt.Fprint(w, fmt.Sprintf("%s/\n", r.RequestURI))
}

func (h *MetadataServer) computeMetadatav1ProjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Project.Attributes) {
		return
	}
	var keys string
	for k, _ := range h.c.ComputeMetadata.V1.Project.Attributes {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, keys)
}

func (h *MetadataServer) computeMetadatav1ProjectAttributesKeyHandler(w http.ResponseWriter, r *http.Request) {
	// recursion isn't applicable
	// todo: ?alt=json returns content-type=application/json but the payload is text..
	vars := mux.Vars(r)
	if val, ok := h.c.ComputeMetadata.V1.Project.Attributes[vars["key"]]; ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, val)
	} else {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprint(w, metadata404Body)
	}
}

func (h *MetadataServer) getServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	switch vars["key"] {

	case "aliases":
		w.Header().Set("Content-Type", "application/text")
		fmt.Fprint(w, "default")
	case "email":
		w.Header().Set("Content-Type", "application/text")
		if os.Getenv(googleServiceAccountEmail) != "" {
			fmt.Fprint(w, os.Getenv(googleServiceAccountEmail))
		} else {
			fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email)
		}
	case "identity":
		k, ok := r.URL.Query()["audience"]
		if !ok {
			httpError(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest, "text/html")
			fmt.Fprint(w, "non-empty audience parameter required")
			return
		}
		idtok, err := h.getIDToken(k[0])
		if err != nil {
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "text/html")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, idtok)
	case "scopes":
		var scopes string
		for _, e := range h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes {
			scopes = scopes + e + "\n"
		}
		w.Header().Set("Content-Type", "application/text")
		fmt.Fprint(w, scopes)
	case "token":
		tok, err := h.getAccessToken()
		if err != nil {
			glog.Errorf("Error getting Token %v\n", err)
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "application/text")
			return
		}
		js, err := json.Marshal(tok)
		if err != nil {
			glog.Errorf("Error unmarshalling Token %v\n", err)
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "application/text")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)

	default:
		httpError(w, http.StatusText(http.StatusNotFound), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

}

func (h *MetadataServer) getAccessToken() (*metadataToken, error) {
	h.tokenMutex.Lock()
	defer h.tokenMutex.Unlock()

	if os.Getenv(googleAccessToken) != "" {
		return &metadataToken{
			AccessToken: os.Getenv(googleAccessToken),
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}, nil
	}

	if h.cfg.flTPM {
		// return a cached token
		if h.creds != nil {
			tok, err := h.creds.TokenSource.Token()
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

		rwc, err := tpm2.OpenTPM(h.cfg.flTPMPath)
		if err != nil {
			glog.Errorf("can't open TPM %s: %v", h.cfg.flTPMPath, err)
			return nil, err
		}
		defer rwc.Close()
		k, err := client.LoadCachedKey(rwc, tpmutil.Handle(h.cfg.flPersistentHandle), nil)
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
				Issuer:    h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Audience:  []string{"https://oauth2.googleapis.com/token"},
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
			},
			strings.Join(h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes, " "),
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
			f, err := io.ReadAll(resp.Body)
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
		h.creds = &google.Credentials{
			ProjectID:   h.c.ComputeMetadata.V1.Project.ProjectID,
			TokenSource: oauth2.StaticTokenSource(&t),
		}
		return &ret, nil
	}
	tok, err := h.creds.TokenSource.Token()
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

func (h *MetadataServer) getIDToken(targetAudience string) (string, error) {
	h.tokenMutex.Lock()
	defer h.tokenMutex.Unlock()

	var idTokenSource oauth2.TokenSource
	var err error

	if os.Getenv(googleIDToken) != "" {
		return os.Getenv(googleIDToken), nil
	}

	ctx := context.Background()
	if h.cfg.flImpersonate {

		idTokenSource, err = impersonate.IDTokenSource(ctx,
			impersonate.IDTokenConfig{
				TargetPrincipal: h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Audience:        targetAudience,
				IncludeEmail:    true,
			},
		)
	} else if h.cfg.flFederate {

		cr, err := iamcredentials.NewIamCredentialsClient(ctx)
		if err != nil {
			return "", err
		}
		defer cr.Close()

		req := &iamcredentialspb.GenerateIdTokenRequest{
			Name:         fmt.Sprintf("projects/-/serviceAccounts/%s", h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email),
			Audience:     targetAudience,
			IncludeEmail: true,
		}
		resp, err := cr.GenerateIdToken(ctx, req)
		if err != nil {
			glog.Errorln(err)
			return "", fmt.Errorf("could not generateID Token %v", err)
		}

		idTokenSource = oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: resp.Token,
		})
	} else if h.cfg.flTPM {
		rwc, err := tpm2.OpenTPM(h.cfg.flTPMPath)
		if err != nil {
			glog.Errorf("can't open TPM %s: %v", h.cfg.flTPMPath, err)
			return "", err
		}
		defer rwc.Close()
		k, err := client.LoadCachedKey(rwc, tpmutil.Handle(h.cfg.flPersistentHandle), nil)
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
				Issuer:    h.c.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
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
			f, err := io.ReadAll(resp.Body)
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
		idTokenSource, err = idtoken.NewTokenSource(ctx, targetAudience, idtoken.WithCredentialsJSON(h.creds.JSON))
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

func (h *MetadataServer) listServiceAccountsIndexHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.ServiceAccounts) {
		return
	}
	var keys string
	for k, _ := range h.c.ComputeMetadata.V1.Instance.ServiceAccounts {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, keys)
}

func (h *MetadataServer) listServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.ServiceAccounts[vars["acct"]]) {
		return
	}
	keys := h.pathListFields(h.c.ComputeMetadata.V1.Instance.ServiceAccounts[vars["acct"]])
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, keys)
}

func (h *MetadataServer) computeMetadatav1InstanceHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance) {
		return
	}
	resp := h.pathListFields(h.c.ComputeMetadata.V1.Instance)
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1InstanceKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	switch vars["key"] {
	case "id":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.ID)
	case "name":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.Name)
	case "hostname":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.Hostname)
	case "zone":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.Zone)
	default:
		httpError(w, http.StatusText(http.StatusNotFound), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")
	return
}

func (h *MetadataServer) computeMetadatav1InstanceAttributesHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.Attributes) {
		return
	}
	var keys string
	for k, _ := range h.c.ComputeMetadata.V1.Instance.Attributes {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, keys)
}

func (h *MetadataServer) computeMetadatav1InstanceAttributesKeyHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.Attributes) {
		return
	}
	vars := mux.Vars(r)
	if val, ok := h.c.ComputeMetadata.V1.Instance.Attributes[vars["key"]]; ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, val)
	} else {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprint(w, metadata404Body)
	}
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) {
		return
	}
	var resp string
	for i, _ := range h.c.ComputeMetadata.V1.Instance.NetworkInterfaces {
		resp = resp + fmt.Sprintf("%d/\n", i)
	}
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i]) {
		return
	}
	resp := h.pathListFields(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i])
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	switch vars["key"] {
	// case "access-configs":
	// 	h.handleBasePathRedirect(w, r)
	// 	return
	case "dns-servers":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].DNSServers)
	case "forwarded-ips":
		h.handleBasePathRedirect(w, r)
		return
	case "gateway":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Gateway)
	case "ip":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].IP)
	case "ip-aliases":
		h.handleBasePathRedirect(w, r)
		return
	case "mac":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Mac)
	case "mtu":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Mtu)
	case "network":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Network)
	case "subnet-mask":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Subnetmask)
	default:
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) {
		return
	}
	var resp string
	for i, _ := range h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs {
		resp = resp + fmt.Sprintf("%d/\n", i)
	}
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	if h.handleRecursion(w, r, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k]) {
		return
	}

	resp := h.pathListFields(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k])
	w.Header().Set("Content-Type", "application/text")
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexRedirectHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	h.handleBasePathRedirect(w, r)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	if len(h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	switch vars["key"] {
	case "external-ip":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k].ExternalIP)
	case "type":
		fmt.Fprint(w, h.c.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k].Type)
	default:
		httpError(w, metadata404Body, http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")

}

func main() {
	ctx := context.Background()
	var cfg serverConfig
	flag.StringVar(&cfg.flInterface, "interface", "127.0.0.1", "interface address to bind to")
	flag.StringVar(&cfg.flPort, "port", ":8080", "port...")
	flag.StringVar(&cfg.flDomainSocket, "domainsocket", "", "listen only on unix socket")
	flag.StringVar(&cfg.flConfigFile, "configFile", "config.json", "config file")

	flag.StringVar(&cfg.serviceAccountFile, "serviceAccountFile", "", "serviceAccountFile...")
	flag.BoolVar(&cfg.flImpersonate, "impersonate", false, "Impersonate a service Account instead of using the keyfile")
	flag.BoolVar(&cfg.flFederate, "federate", false, "Use Workload Identity Federation ADC")
	flag.BoolVar(&cfg.flTPM, "tpm", false, "Use TPM to get access and id_token")
	flag.StringVar(&cfg.flTPMPath, "tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	flag.IntVar(&cfg.flPersistentHandle, "persistentHandle", 0x81008000, "Handle value")

	flag.Parse()

	glog.Infof("Starting GCP metadataserver")

	var a MetadataServer
	r := mux.NewRouter()
	r.StrictSlash(false)

	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}", http.HandlerFunc(a.getServiceAccountHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/", http.HandlerFunc(a.listServiceAccountHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/", http.HandlerFunc(a.listServiceAccountsIndexHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}/{key}", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceAccessConfigsKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}/", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexRedirectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceAccessConfigsHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/{key}", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/", http.HandlerFunc(a.computeMetadatav1InstanceNetworkInterfaceHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/", http.HandlerFunc(a.computeMetadatav1InstanceNetworkHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance/attributes/{key}", http.HandlerFunc(a.computeMetadatav1InstanceAttributesKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/attributes/", http.HandlerFunc(a.computeMetadatav1InstanceAttributesHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/attributes", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/{key}", http.HandlerFunc(a.computeMetadatav1InstanceKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/", http.HandlerFunc(a.computeMetadatav1InstanceHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/project/project-id", http.HandlerFunc(a.computeMetadatav1ProjectProjectIDHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/numeric-project-id", http.HandlerFunc(a.computeMetadatav1ProjectNumericProjectIDHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes/{key}", http.HandlerFunc(a.computeMetadatav1ProjectAttributesKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes/", http.HandlerFunc(a.computeMetadatav1ProjectAttributesHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/", http.HandlerFunc(a.computeMetadatav1ProjectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/", http.HandlerFunc(a.computeMetadatav1Handler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/", http.HandlerFunc(a.computeMetadataHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata", http.HandlerFunc(a.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/", http.HandlerFunc(a.rootHandler)).Methods(http.MethodGet)

	r.NotFoundHandler = http.HandlerFunc(a.notFound)

	http.Handle("/", a.checkMetadataHeaders(r))

	var l net.Listener
	var err error
	var configCliams claims
	var creds *google.Credentials

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

	configData, err := os.ReadFile(cfg.flConfigFile)
	if err != nil {
		glog.Errorf("Error listening to domain socket: %v\n", err)

	}
	err = json.Unmarshal(configData, &configCliams)
	if err != nil {
		glog.Errorf("Error parsing json: %v\n", err)
		os.Exit(-1)
	}

	srv := &http.Server{}
	http2.ConfigureServer(srv, &http2.Server{})

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	_, ok := configCliams.ComputeMetadata.V1.Instance.ServiceAccounts["default"]
	if !ok {
		glog.Errorf("default service account must be set")
		os.Exit(-1)
	}

	if cfg.flImpersonate {
		glog.Infoln("Using Service Account Impersonation")

		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: configCliams.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
			Scopes:          configCliams.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes,
		})
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			os.Exit(1)
		}

		creds = &google.Credentials{
			TokenSource: ts,
		}
	} else if cfg.flFederate {
		glog.Infoln("Using Workload Identity Federation")

		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			glog.Error("GOOGLE_APPLICATION_CREDENTIALSh --federate")
			os.Exit(1)
		}

		glog.Infof("Federation path: %s", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		var err error
		creds, err = google.FindDefaultCredentials(ctx, configCliams.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
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

		glog.Infoln("Using serviceAccountFile for credentials")
		var err error
		//creds, err = google.FindDefaultCredentials(ctx, tokenScopes)
		data, err := os.ReadFile(cfg.serviceAccountFile)
		if err != nil {
			glog.Errorf("Unable to read serviceAccountFile %v", err)
			os.Exit(1)
		}
		creds, err = google.CredentialsFromJSON(ctx, data, configCliams.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes...)
		if err != nil {
			glog.Errorf("Unable to parse serviceAccountFile %v ", err)
			os.Exit(1)
		}

		if creds.ProjectID != configCliams.ComputeMetadata.V1.Project.ProjectID {
			glog.Warning("ProjectID in config file does not match project from credentials")
		}
	}

	a = MetadataServer{
		cfg:   cfg,
		creds: creds,
		c:     configCliams,
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
