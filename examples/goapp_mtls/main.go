package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	//"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

/*

## start metadata server with mtls
go run cmd/main.go   -logtostderr   -alsologtostderr -v 40   -port :8080 --configFile=`pwd`/config.json \
  --serviceAccountFile certs/metadata-sa.json \
  --usemTLS --serverCert certs/server.crt --serverKey certs/server.key --rootCAmTLS certs/root.crt


export GCE_METADATA_HOST=localhost:8080
go run main.go
*/

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
	tr.rtp = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dc,
		TLSHandshakeTimeout: 400 * time.Millisecond,
		TLSClientConfig:     tr.tlsConfig,
	}
	return tr
}

func (tr *gceMetadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Add("Metadata-Flavor", "Google")
	return tr.rtp.RoundTrip(r)
}

const (
	bucketName = "core-eso-bucket"
)

func main() {

	ctx := context.Background()

	caCert, err := os.ReadFile("../../certs/root.crt")
	if err != nil {
		fmt.Printf("error reading cacert %v", err)
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	certs, err := tls.LoadX509KeyPair("../../certs/client.crt", "../../certs/client.key")
	if err != nil {
		fmt.Printf("error reading certs %v", err)
		os.Exit(1)
	}

	tlsconfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{certs},
	}

	client := &http.Client{
		Transport: GCEMetadataTLSTransport(tlsconfig),
	}

	projectIDResp, err := client.Get("https://metadata.google.internal/computeMetadata/v1/project/project-id")
	if err != nil {
		fmt.Printf("error reading projectIDResp %v", err)
		os.Exit(1)
	}

	projectIDBytes, err := io.ReadAll(projectIDResp.Body)
	if err != nil {
		fmt.Printf("error reading projectIDBytes %v", err)
		os.Exit(1)
	}
	defer projectIDResp.Body.Close()
	fmt.Printf("ProjectID: %s\n", string(projectIDBytes))

	accessTokenResp, err := client.Get("https://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
	if err != nil {
		fmt.Printf("error reading accessTokenResp %v", err)
		os.Exit(1)
	}

	accessTokenBytes, err := io.ReadAll(accessTokenResp.Body)
	if err != nil {
		fmt.Printf("error reading accessTokenBytes %v", err)
		os.Exit(1)
	}
	defer accessTokenResp.Body.Close()

	tok := &oauth2.Token{}
	err = json.Unmarshal(accessTokenBytes, tok)
	if err != nil {
		fmt.Println("Error in JSON oauth2Token", err)

	}

	fmt.Printf("AccessToken: %s\n", string(accessTokenBytes))

	// note, i'm using a staticTokeSource here.
	//  a really easy TODO is to write custom token source which'll allow automatic acquisitions refresh of these tokens
	//   eg  https://github.com/salrashid123/gcp_process_credentials_go/blob/main/external.go#L36
	//  for example, create a
	//    sts, err := ComputeTokenSourceMTLS(&ComputeTokenSourceMTLSConfig{ CACert: *ca, Cert: *pub, Key: *key })
	//
	sts := oauth2.StaticTokenSource(tok)

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(sts))
	if err != nil {
		panic(err)
	}
	defer storageClient.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	it := storageClient.Bucket(bucketName).Objects(ctx, nil)
	for {
		oattrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("Bucket: %v\n", oattrs.Name)
	}

	// c := metadata.NewClient(client)
	// // get arbitrary metadata values directly;  this won't work because the metadata package does not support client certs
	// instanceID, err := c.InstanceIDWithContext(ctx)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("InstanceID %s\n", instanceID)

}
