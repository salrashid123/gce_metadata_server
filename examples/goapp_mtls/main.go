package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	//"cloud.google.com/go/compute/metadata"
	"mtlstokensource"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
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
		Transport: mtlstokensource.GCEMetadataTLSTransport(tlsconfig),
	}

	// get arbitrary metadata using custom http client
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

	/// get arbitrary data from metadata server using metadata library
	c := metadata.NewClient(client)
	instanceID, err := c.InstanceIDWithContext(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("InstanceID %s\n", instanceID)

	mts, err := mtlstokensource.MtlsTokenSource(&mtlstokensource.MtlsTokenConfig{
		RootCA:         *caCertPool,
		TLSCertificate: certs,
	})
	if err != nil {
		fmt.Printf("error reading tokensource %v", err)
		os.Exit(1)
	}
	tok, err := mts.Token()
	if err != nil {
		fmt.Printf("error reading token %v", err)
		os.Exit(1)
	}
	fmt.Printf("AccessToken: %s\n", tok.AccessToken)

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(mts))
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

}
