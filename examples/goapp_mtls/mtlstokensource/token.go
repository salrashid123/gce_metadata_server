package mtlstokensource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type MtlsTokenConfig struct {
	RootCA         x509.CertPool
	TLSCertificate tls.Certificate
}

type gceMetadataTransport struct {
	rtp       http.RoundTripper
	tlsConfig *tls.Config
}

func GCEMetadataTLSTransport(tlsconfig *tls.Config) *gceMetadataTransport {
	tr := &gceMetadataTransport{
		tlsConfig: tlsconfig,
	}

	myDialer := &net.Dialer{
		Timeout: 500 * time.Millisecond,
	}
	dc := func(ctx context.Context, network, address string) (net.Conn, error) {
		overrideAddress := os.Getenv("GCE_METADATA_HOST")
		if overrideAddress == "" {
			overrideAddress = "metadata.google.internal:443"
		}
		return myDialer.DialContext(ctx, network, overrideAddress)
	}

	tr.tlsConfig.ServerName = "metadata.google.internal"
	tr.rtp = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dc,
		TLSHandshakeTimeout: 400 * time.Millisecond,
		TLSClientConfig:     tr.tlsConfig,
	}
	return tr
}

func (tr *gceMetadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "https"
	r.Header.Add("Metadata-Flavor", "Google")
	return tr.rtp.RoundTrip(r)
}

const ()

func MtlsTokenSource(tokenConfig *MtlsTokenConfig) (oauth2.TokenSource, error) {

	tlsConfig := &tls.Config{
		RootCAs:      &tokenConfig.RootCA,
		Certificates: []tls.Certificate{tokenConfig.TLSCertificate},
	}

	return &mtlsTokenSource{
		refreshMutex: &sync.Mutex{},
		mtlsToken:    oauth2.Token{},
		tlsConfig:    tlsConfig,
	}, nil
}

type mtlsTokenSource struct {
	refreshMutex *sync.Mutex
	mtlsToken    oauth2.Token
	tlsConfig    *tls.Config
}

func (ts *mtlsTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.mtlsToken.Valid() {
		return &ts.mtlsToken, nil
	}

	client := &http.Client{
		Transport: GCEMetadataTLSTransport(ts.tlsConfig),
		Timeout:   time.Duration(100) * time.Millisecond,
	}

	accessTokenResp, err := client.Get("https://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
	if err != nil {
		return nil, err
	}

	accessTokenBytes, err := io.ReadAll(accessTokenResp.Body)
	if err != nil {
		return nil, err
	}
	defer accessTokenResp.Body.Close()

	tok := &oauth2.Token{}
	err = json.Unmarshal(accessTokenBytes, tok)
	if err != nil {
		return nil, err
	}

	return tok, nil

}
