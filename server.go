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

// Creates a Google Cloud Platform local MetadataServer used for test, emulation or to run
// applications outside of a google cloud environment.
//
// Supports reading credentials from a service account key file, workload federation,
// statically or from a key saved on a Trusted Platform Module (TPM).
//
// [GCE Metadata Server Emulator]: https://github.com/salrashid123/gce_metadata_server
package mds

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"context"
	"fmt"

	"net/http"
	"net/url"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/golang/glog"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"golang.org/x/oauth2"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	iamcredentials "cloud.google.com/go/iam/credentials/apiv1"
	iamcredentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configures and manages the server and is used as a receiver to start and stop the server.
//
// Applications can initialize the metadata server using this struct by providing it
// with the credentials to use, the claims it provides as well as runtime specifications
// like the port and interface to use
type MetadataServer struct {
	tokenMutex   sync.Mutex
	srv          *http.Server
	initNew      bool
	Creds        *google.Credentials // credentials to use
	Claims       Claims              // values for the runtime attributes and values the metadata server returns
	ServerConfig ServerConfig        // base system configuration (listen interface, port, etc)
}

var (
	// hostHeaders = []string{"metadata", "metadata.google.internal", "169.254.169.254"}

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "metadata_endpoint_latency_seconds",
		Help: "Duration of HTTP requests.",
	}, []string{"path"})

	pathReqs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "metadata_endpoint_path_requests",
			Help: "backend status, partitioned by status code and path.",
		},
		[]string{"code", "path"},
	)
)

const (
	emailScope                = "https://www.googleapis.com/auth/userinfo.email"
	cloudPlatformScope        = "https://www.googleapis.com/auth/cloud-platform"
	googleAccessToken         = "GOOGLE_ACCESS_TOKEN"
	googleIDToken             = "GOOGLE_ID_TOKEN"
	googleProjectID           = "GOOGLE_PROJECT_ID"
	googleProjectNumber       = "GOOGLE_NUMERIC_PROJECT_ID"
	googleServiceAccountEmail = "GOOGLE_SERVICE_ACCOUNT"

	defaultMetricsPath      = "/metrics"
	defaultMetricsInterface = "127.0.0.1"
	defaultMetricsPort      = "9000"
)

// Configures the base runtime for the metadata server.
// Set the port, bind-address and what mode this server will acquire credentials through
type ServerConfig struct {
	BindInterface string // interface to bind to (default 127.0.0.1)
	Port          string // port to listen on (default :8080)
	DomainSocket  string // toggle if unix domain sockets should be used.

	MetricsEnabled   bool   // flag if prometheus metrics are enabled (default false)
	MetricsInterface string // interface to bind for metrics (default 127.0.0.1)
	MetricsPort      string // port for the metrics prometheus endpoint (default :9000)
	MetricsPath      string // path for metrics endpoint (default /metrics)

	Impersonate bool // toggle if provided default credentials should be impersonated (default: false)
	Federate    bool // toggle if workload federation should be used (default: false)

	UseTPM           bool               // toggle if TPM should be used for credentials (default: false)
	TPMDevice        io.ReadWriteCloser // initialized transport for the TPM
	Handle           tpm2.TPMHandle     // initialized  handle to the key
	AuthSession      tpmjwt.Session     // auth session to use
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption

	UsemTLS    bool   // toggle if mtls is used (default: false)
	RootCAmTLS string // ca to validate client certs (default "")
	ServerCert string // server certificate for mtls (default: "")
	ServerKey  string // server key for mtls (default: "")
}

func notFoundErrorHandler(path string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang=en>
  <meta charset=utf-8>
  <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
  <title>Error 404 (Not Found)!!1</title>
  <style>
     *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7%% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100%% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0%% 0%%/100%% 100%%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100%% 100%%}}#logo{display:inline-block;height:54px;width:150px}
  </style>
  <a href=//www.google.com/><span id=logo aria-label=Google></span></a>
  <p><b>404.</b> <ins>That’s an error.</ins>
  <p>The requested URL <code>%s<code> was not found on this server.  <ins>That’s all we know.</ins>`, path)
}

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		timer := prometheus.NewTimer(httpDuration.WithLabelValues(path))
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}

func httpError(w http.ResponseWriter, error string, code int, contentType string) {
	if contentType == "" {
		contentType = "text/html; charset=UTF-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

type metadataToken struct {
	AccessToken string `json:"access_token"`
	// metadata server returns an "expires_in" while oauth2.Token returns Expiry time.time
	ExpiresIn int    `json:"expires_in"`
	TokenType string `json:"token_type"`
}

type serviceAccountDetails struct {
	Aliases  []string `json:"aliases" altjson:"aliases"`
	Email    string   `json:"email" altjson:"email"`
	Identity string   `json:"identity" altjson:"identity"`
	Scopes   []string `json:"scopes" altjson:"scopes"`
	Token    string   `json:"token" altjson:"token"`
}

// Base claims returned by the metadata server
// Claims are structured in the same format as provided by a 'real' metadata server
//
// eg   `curl -v -H 'Metadata-Flavor: Google' http://metadata/computeMetadata/v1/?recursive=true`
type Claims struct {
	ComputeMetadata ComputeMetadata `json:"computeMetadata"  altjson:"computeMetadata"`
}

type ComputeMetadata struct {
	V1 V1 `json:"v1" altjson:"v1"`
}

// Configuration of the v1 settings for the metadata server.
type V1 struct {
	Instance Instance `json:"instance" altjson:"instance"`
	Oslogin  OSlogin  `json:"oslogin"  altjson:"oslogin"`
	Project  Project  `json:"project"  altjson:"project"`
}

type Instance struct {
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

// OSLogin configuration to apply
type OSlogin struct {
	Authenticate struct {
		Sessions struct {
		} `json:"sessions" altjson:"sessions"`
	} `json:"authenticate" altjson:"authenticate"`
}

// Project configuration to apply
type Project struct {
	Attributes       map[string]string `json:"attributes" altjson:"attributes"`
	NumericProjectID int64             `json:"numericProjectId" altjson:"numeric-project-id"`
	ProjectID        string            `json:"projectId" altjson:"project-id"`
}

func (h *MetadataServer) checkMetadataHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		glog.V(10).Infof("Got Request: path[%s] query[%s]", r.URL.Path, r.URL.RawQuery)

		for k, v := range r.Header {
			glog.V(20).Infof("%s: %s", k, v)
		}

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

		if flavor == "" && r.RequestURI != "/" {
			httpError(w, "Missing required header \"Metadata-Flavor\": \"Google\"", http.StatusForbidden, "text/html; charset=UTF-8")
			return
		}
		if flavor != "Google" && r.RequestURI != "/" {
			glog.Errorf("Incorrect metadata flavor provided %s", flavor)
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

func getETag(body []byte) string {
	hash := md5.Sum(body)
	etag := fmt.Sprintf("%x", hash[8:])
	return etag
}

func (h *MetadataServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.Claims)
	fmt.Fprint(w, resp)
}

func (h *MetadataServer) notFound(w http.ResponseWriter, r *http.Request) {
	glog.Infof("%s called but is not implemented", r.URL.Path)
	httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
}

func (h *MetadataServer) computeMetadataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.Claims.ComputeMetadata)
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1Handler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1) {
		return
	}
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.Claims.ComputeMetadata.V1)
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1ProjectHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Project) {
		return
	}
	w.Header().Set("Content-Type", "application/text")
	resp := h.pathListFields(h.Claims.ComputeMetadata.V1.Project)
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1ProjectProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	var resp []byte
	w.Header().Set("Content-Type", "application/text")
	if os.Getenv(googleProjectID) != "" {
		resp = []byte(os.Getenv(googleProjectID))

	} else {
		resp = []byte(h.Claims.ComputeMetadata.V1.Project.ProjectID)
	}
	e := getETag(resp)
	w.Header()["ETag"] = []string{e}
	w.Write(resp)
}

func (h *MetadataServer) computeMetadatav1ProjectNumericProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	var resp []byte
	w.Header().Set("Content-Type", "application/text")
	if os.Getenv(googleProjectNumber) != "" {
		resp = []byte(os.Getenv(googleProjectNumber))
	} else {
		resp = []byte(strconv.FormatInt(h.Claims.ComputeMetadata.V1.Project.NumericProjectID, 10))
	}
	e := getETag(resp)
	w.Header()["ETag"] = []string{e}
	w.Write(resp)
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
			e := getETag(jsonResponse)
			w.Header()["ETag"] = []string{e}
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
	w.Write([]byte(fmt.Sprintf("%s/\n", r.RequestURI)))
}

func (h *MetadataServer) computeMetadatav1ProjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Project.Attributes) {
		return
	}
	var keys string
	for k, _ := range h.Claims.ComputeMetadata.V1.Project.Attributes {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")

	e := getETag([]byte(keys))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(keys))
}

func (h *MetadataServer) computeMetadatav1ProjectAttributesKeyHandler(w http.ResponseWriter, r *http.Request) {
	// recursion isn't applicable
	// todo: ?alt=json returns content-type=application/json but the payload is text..
	vars := mux.Vars(r)
	if val, ok := h.Claims.ComputeMetadata.V1.Project.Attributes[vars["key"]]; ok {
		e := getETag([]byte(val))
		w.Header()["ETag"] = []string{e}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(val))
	} else {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprintf(w, "%s", notFoundErrorHandler(r.URL.Path))
	}
}

func (h *MetadataServer) getServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	var resp []byte
	vars := mux.Vars(r)
	switch vars["key"] {

	case "aliases":
		w.Header().Set("Content-Type", "application/text")
		resp = []byte("default")
	case "email":
		w.Header().Set("Content-Type", "application/text")
		if os.Getenv(googleServiceAccountEmail) != "" {
			resp = []byte(os.Getenv(googleServiceAccountEmail))
		} else {
			resp = []byte(h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email)
		}
	case "identity":
		k, ok := r.URL.Query()["audience"]
		if !ok {
			if h.ServerConfig.MetricsEnabled {
				defer pathReqs.WithLabelValues(http.StatusText(http.StatusBadRequest), r.URL.Path).Inc()
			}
			httpError(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest, "text/html")
			fmt.Fprint(w, "non-empty audience parameter required")
			return
		}
		idtok, err := h.getIDToken(k[0])
		if err != nil {
			if h.ServerConfig.MetricsEnabled {
				defer pathReqs.WithLabelValues(http.StatusText(http.StatusInternalServerError), r.URL.Path).Inc()
			}
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "text/html")
			return
		}
		if h.ServerConfig.MetricsEnabled {
			defer pathReqs.WithLabelValues(http.StatusText(http.StatusOK), r.URL.Path).Inc()
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, idtok)
		return
	case "scopes":
		var scopes string
		for _, e := range h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Scopes {
			scopes = scopes + e + "\n"
		}
		w.Header().Set("Content-Type", "application/text")
		resp = []byte(scopes)
	case "token":

		var scopes []string
		k, ok := r.URL.Query()["scopes"]
		if ok {
			glog.V(10).Infof("access_token requested with scopes: [%s]", scopes)
			scopes = strings.Split(k[0], ",")
		}
		tok, err := h.getAccessToken(scopes)
		if err != nil {
			if h.ServerConfig.MetricsEnabled {
				defer pathReqs.WithLabelValues(http.StatusText(http.StatusInternalServerError), r.URL.Path).Inc()
			}
			glog.Errorf("Error getting Token %v\n", err)
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "application/text")
			return
		}
		js, err := json.Marshal(tok)
		if err != nil {
			if h.ServerConfig.MetricsEnabled {
				defer pathReqs.WithLabelValues(http.StatusText(http.StatusInternalServerError), r.URL.Path).Inc()
			}
			glog.Errorf("Error unmarshalling Token %v\n", err)
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "application/text")
			return
		}
		if h.ServerConfig.MetricsEnabled {
			defer pathReqs.WithLabelValues(http.StatusText(http.StatusOK), r.URL.Path).Inc()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return

	default:
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) getAccessToken(scopes []string) (*metadataToken, error) {
	h.tokenMutex.Lock()
	defer h.tokenMutex.Unlock()

	var ts oauth2.TokenSource
	if os.Getenv(googleAccessToken) != "" {
		ts = oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: os.Getenv(googleAccessToken),
			Expiry:      time.Now().Add(time.Second * 3600),
			TokenType:   "Bearer",
		})

	} else {
		ts = h.Creds.TokenSource
	}

	tok, err := ts.Token()
	if err != nil {
		glog.Errorf("ERROR:  could not get Token: %v", err)
		return nil, err
	}
	now := time.Now().UTC()
	diff := tok.Expiry.Sub(now)
	return &metadataToken{
		AccessToken: tok.AccessToken,
		ExpiresIn:   int(diff.Round(time.Second).Seconds()),
		TokenType:   "Bearer",
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
	if h.ServerConfig.Impersonate {

		idTokenSource, err = impersonate.IDTokenSource(ctx,
			impersonate.IDTokenConfig{
				TargetPrincipal: h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
				Audience:        targetAudience,
				IncludeEmail:    true,
			},
		)
		if err != nil {
			glog.Errorln(err)
			return "", fmt.Errorf("could not generateID Token %v", err)
		}
	} else if h.ServerConfig.Federate {

		cr, err := iamcredentials.NewIamCredentialsClient(ctx)
		if err != nil {
			return "", err
		}
		defer cr.Close()

		req := &iamcredentialspb.GenerateIdTokenRequest{
			Name:         fmt.Sprintf("projects/-/serviceAccounts/%s", h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email),
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
	} else if h.ServerConfig.UseTPM {
		iat := time.Now()
		exp := iat.Add(time.Second * 10)

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			jwt.RegisteredClaims{
				Issuer:    h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email,
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

		glog.V(20).Infof("TPM credentials using using handle  %d", h.ServerConfig.Handle)
		config := &tpmjwt.TPMConfig{
			TPMDevice:        h.ServerConfig.TPMDevice,
			Handle:           h.ServerConfig.Handle,
			AuthSession:      h.ServerConfig.AuthSession,
			EncryptionHandle: h.ServerConfig.EncryptionHandle,
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

		hreq, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
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
		idTokenSource, err = idtoken.NewTokenSource(ctx, targetAudience, idtoken.WithCredentialsJSON(h.Creds.JSON))
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
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts) {
		return
	}
	var keys string
	for k, _ := range h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(keys))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(keys))
}

func (h *MetadataServer) listServiceAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts[vars["acct"]]) {
		return
	}
	keys := h.pathListFields(h.Claims.ComputeMetadata.V1.Instance.ServiceAccounts[vars["acct"]])
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(keys))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(keys))
}

func (h *MetadataServer) computeMetadatav1InstanceHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance) {
		return
	}
	resp := h.pathListFields(h.Claims.ComputeMetadata.V1.Instance)
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))

}

func (h *MetadataServer) computeMetadatav1InstanceKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var res []byte
	var err error

	// default content-type
	w.Header().Set("Content-Type", "application/text")
	switch vars["key"] {
	case "id":
		res = []byte(strconv.FormatInt(h.Claims.ComputeMetadata.V1.Instance.ID, 10))
	case "name":
		res = []byte(h.Claims.ComputeMetadata.V1.Instance.Name)
	case "hostname":
		res = []byte(h.Claims.ComputeMetadata.V1.Instance.Hostname)
	case "zone":
		res = []byte(h.Claims.ComputeMetadata.V1.Instance.Zone)
	case "machine-type":
		res = []byte(h.Claims.ComputeMetadata.V1.Instance.MachineType)
	case "maintenance-event":
		res = []byte(h.Claims.ComputeMetadata.V1.Instance.MaintenanceEvent)
	case "tags":
		res, err = json.Marshal(h.Claims.ComputeMetadata.V1.Instance.Tags)
		if err != nil {
			glog.Errorf("Error converting value to JSON %v\n", err)
			httpError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, "text/plain; charset=UTF-8")
			return
		}
		w.Header().Set("Content-Type", "application/json")
	default:
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	e := getETag(res)
	w.Header()["ETag"] = []string{e}
	w.Write(res)
}

func (h *MetadataServer) computeMetadatav1InstanceAttributesHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.Attributes) {
		return
	}
	var keys string
	for k, _ := range h.Claims.ComputeMetadata.V1.Instance.Attributes {
		keys = keys + k + "\n"
	}
	w.Header().Set("Content-Type", "application/text")

	e := getETag([]byte(keys))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(keys))
}

func (h *MetadataServer) computeMetadatav1InstanceAttributesKeyHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.Attributes) {
		return
	}
	vars := mux.Vars(r)
	if val, ok := h.Claims.ComputeMetadata.V1.Instance.Attributes[vars["key"]]; ok {
		e := getETag([]byte(val))
		w.Header()["ETag"] = []string{e}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(val))
	} else {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprintf(w, "%s", notFoundErrorHandler(r.URL.Path))
	}
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkHandler(w http.ResponseWriter, r *http.Request) {
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) {
		return
	}
	var resp string
	for i, _ := range h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces {
		resp = resp + fmt.Sprintf("%d/\n", i)
	}
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i]) {
		return
	}
	resp := h.pathListFields(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i])
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceKeyHandler(w http.ResponseWriter, r *http.Request) {
	var resp []byte
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	switch vars["key"] {
	// case "access-configs":
	// 	h.handleBasePathRedirect(w, r)
	// 	return
	case "dns-servers":
		// gce metadata server default returns "application/text" for dns-servers
		resp = []byte(strings.Join(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].DNSServers, "\n"))
	case "forwarded-ips":
		h.handleBasePathRedirect(w, r)
		return
	case "gateway":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Gateway)
	case "ip":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].IP)
	case "ip-aliases":
		h.handleBasePathRedirect(w, r)
		return
	case "mac":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Mac)
	case "mtu":
		resp = []byte(strconv.Itoa(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Mtu))
	case "network":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Network)
	case "subnet-mask":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].Subnetmask)
	default:
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) {
		return
	}
	var resp string
	for i, _ := range h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs {
		resp = resp + fmt.Sprintf("%d/\n", i)
	}
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	if h.handleRecursion(w, r, h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k]) {
		return
	}

	resp := h.pathListFields(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k])
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexRedirectHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	h.handleBasePathRedirect(w, r)
}

func (h *MetadataServer) computeMetadatav1InstanceNetworkInterfaceAccessConfigsKeyHandler(w http.ResponseWriter, r *http.Request) {
	var resp []byte
	vars := mux.Vars(r)
	i, err := strconv.Atoi(vars["index"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces) < i+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	k, err := strconv.Atoi(vars["index2"])
	if err != nil {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	if len(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs) < k+1 {
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}

	switch vars["key"] {
	case "external-ip":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k].ExternalIP)
	case "type":
		resp = []byte(h.Claims.ComputeMetadata.V1.Instance.NetworkInterfaces[i].AccessConfigs[k].Type)
	default:
		httpError(w, notFoundErrorHandler(r.URL.Path), http.StatusNotFound, "text/html; charset=UTF-8")
		return
	}
	w.Header().Set("Content-Type", "application/text")
	e := getETag([]byte(resp))
	w.Header()["ETag"] = []string{e}
	w.Write([]byte(resp))
}

// Start running the metadata server using the configuration provided through `NewMetadataServer()`
func (h *MetadataServer) Start() error {

	if !h.initNew {
		return errors.New("metadata server was not created using NewMetadataServer()")
	}

	r := mux.NewRouter()
	r.StrictSlash(false)

	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}", http.HandlerFunc(h.getServiceAccountHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/", http.HandlerFunc(h.listServiceAccountHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts/", http.HandlerFunc(h.listServiceAccountsIndexHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/service-accounts", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}/{key}", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceAccessConfigsKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}/", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceAccessConfigsIndexRedirectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceAccessConfigsHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/{key}", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/", http.HandlerFunc(h.computeMetadatav1InstanceNetworkInterfaceHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces/", http.HandlerFunc(h.computeMetadatav1InstanceNetworkHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/network-interfaces", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/instance/attributes/{key}", http.HandlerFunc(h.computeMetadatav1InstanceAttributesKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/attributes/", http.HandlerFunc(h.computeMetadatav1InstanceAttributesHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/attributes", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/{key}", http.HandlerFunc(h.computeMetadatav1InstanceKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance/", http.HandlerFunc(h.computeMetadatav1InstanceHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/instance", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/project/project-id", http.HandlerFunc(h.computeMetadatav1ProjectProjectIDHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/numeric-project-id", http.HandlerFunc(h.computeMetadatav1ProjectNumericProjectIDHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes/{key}", http.HandlerFunc(h.computeMetadatav1ProjectAttributesKeyHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes/", http.HandlerFunc(h.computeMetadatav1ProjectAttributesHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/attributes", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project/", http.HandlerFunc(h.computeMetadatav1ProjectHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1/project", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/v1/", http.HandlerFunc(h.computeMetadatav1Handler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata/v1", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/computeMetadata/", http.HandlerFunc(h.computeMetadataHandler)).Methods(http.MethodGet)
	r.Handle("/computeMetadata", http.HandlerFunc(h.handleBasePathRedirect)).Methods(http.MethodGet)

	r.Handle("/", http.HandlerFunc(h.rootHandler)).Methods(http.MethodGet)

	r.NotFoundHandler = http.HandlerFunc(h.notFound)

	m := http.NewServeMux()
	r.Use(prometheusMiddleware)
	m.Handle("/", h.checkMetadataHeaders(r))

	var l net.Listener
	var err error

	h.srv = &http.Server{Handler: m}

	if h.ServerConfig.DomainSocket != "" {
		glog.Infof("domain socket specified, ignoring TCP listers, %s", h.ServerConfig.DomainSocket)
		l, err = net.Listen("unix", h.ServerConfig.DomainSocket)
		if err != nil {
			glog.Errorf("Error listening to domain socket: %v\n", err)
			return err
		}
	} else if h.ServerConfig.UsemTLS {
		clientCaCert, err := os.ReadFile(h.ServerConfig.RootCAmTLS)
		if err != nil {
			glog.Errorf("Error reading mtls ca: %v\n", err)
			return err
		}
		clientCaCertPool := x509.NewCertPool()
		clientCaCertPool.AppendCertsFromPEM(clientCaCert)

		serverCertBytes, err := os.ReadFile(h.ServerConfig.ServerCert)
		if err != nil {
			glog.Errorf("ERROR:  Failed to  parse server certificate: %s", err)
			return err
		}

		blockpulic, _ := pem.Decode(serverCertBytes)

		clientCertificate, err := x509.ParseCertificate(blockpulic.Bytes)
		if err != nil {
			glog.Errorf("ERROR:  Failed to  parse certificate: %s", err)
			return err
		}

		serverKeyBytes, err := os.ReadFile(h.ServerConfig.ServerKey)
		if err != nil {
			glog.Errorf("ERROR:  Failed to  parse server key: %s", err)
			return err
		}

		blockKey, _ := pem.Decode(serverKeyBytes)

		clientKey, err := x509.ParsePKCS8PrivateKey(blockKey.Bytes)
		if err != nil {
			glog.Errorf("ERROR:  Failed to  parse ec key: %s", err)
			return err
		}

		tlsCrt := tls.Certificate{
			Certificate: [][]byte{clientCertificate.Raw},
			Leaf:        clientCertificate,
			PrivateKey:  clientKey,
		}

		tc := &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCaCertPool,
			Certificates: []tls.Certificate{tlsCrt},
		}

		glog.Infof("tcp TLS socket specified %s", fmt.Sprintf("%s%s", h.ServerConfig.BindInterface, h.ServerConfig.Port))
		l, err = tls.Listen("tcp", fmt.Sprintf("%s%s", h.ServerConfig.BindInterface, h.ServerConfig.Port), tc)
		if err != nil {
			glog.Errorf("Error listening to tcp socket: %v\n", err)
			return err
		}
	} else {
		glog.Infof("tcp socket specified %s", fmt.Sprintf("%s%s", h.ServerConfig.BindInterface, h.ServerConfig.Port))
		l, err = net.Listen("tcp", fmt.Sprintf("%s%s", h.ServerConfig.BindInterface, h.ServerConfig.Port))
		if err != nil {
			glog.Errorf("Error listening to tcp socket: %v\n", err)
			return err
		}
	}

	if h.ServerConfig.MetricsEnabled {
		if h.ServerConfig.MetricsPath == "" {
			h.ServerConfig.MetricsPath = defaultMetricsPath
		}
		if h.ServerConfig.MetricsInterface == "" {
			h.ServerConfig.MetricsInterface = defaultMetricsInterface
		}
		if h.ServerConfig.MetricsPort == "" {
			h.ServerConfig.MetricsPort = defaultMetricsPort
		}
		go func() {
			http.Handle(h.ServerConfig.MetricsPath, promhttp.Handler())
			glog.Error(http.ListenAndServe(fmt.Sprintf("%s:%s", h.ServerConfig.MetricsInterface, h.ServerConfig.MetricsPort), nil))
		}()
	}

	go func() {
		if err := h.srv.Serve(l); err != nil && err != http.ErrServerClosed {
			// probably should use glog.Fatal() or propagate this err back to the main function
			glog.Errorf("Critical error during Serve: : %s\n", err)
			return
		}
	}()

	return nil
}

// Stop a running metadata server
func (h *MetadataServer) Shutdown() error {
	ctx := context.Background()
	if err := h.srv.Shutdown(ctx); err != nil {
		glog.Errorf("Server Shutdown Failed:%+v", err)
		return err
	}
	glog.Infoln("Server Exited Properly")
	return nil
}

// Configure a new MetadataServer instance.
//
// This will not start the instance (to do that, use the .Start() method).
//
// - ServerConfig:  This configures the core/baseline runtime.  Specify the interface,port and credential scheme to use
//
// - google.Credentials:  Credentials to use for the access or id_token
//
// - Claims:  The runtime claims returned by the metadata server
func NewMetadataServer(ctx context.Context, serverConfig *ServerConfig, creds *google.Credentials, claims *Claims) (*MetadataServer, error) {

	// do some input validation here
	if serverConfig == nil || creds == nil || claims == nil {
		return nil, errors.New("serverConfig, credential and claims cannot be nil")
	}

	if serverConfig.UseTPM && &serverConfig.Handle == nil {
		return nil, errors.New("Handle must be set if useTPM is enabled")
	}

	h := &MetadataServer{
		Creds:        creds,
		Claims:       *claims,
		ServerConfig: *serverConfig,
		initNew:      true, // confirms the MetadataServer was started with NewMetadataServer()
	}
	return h, nil
}

func GetEnv(key, fallback string, fromArg string) string {
	if fromArg != "" {
		return fromArg
	}
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func GetExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}
