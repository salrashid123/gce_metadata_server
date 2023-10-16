package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	domainSocket = "/tmp/metadata.sock"
)

type metadataTransport struct {
	tr http.RoundTripper
}

func (t *metadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Path = strings.TrimPrefix(r.URL.Path, domainSocket)
	return t.tr.RoundTrip(r)
}

func main() {

	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", domainSocket)
			},
		},
	}

	httpClient.Transport = &metadataTransport{tr: httpClient.Transport}
	mclient := metadata.NewClient(&httpClient)

	var err error
	projectID, err := mclient.ProjectID()
	if err != nil {
		panic(err)
	}
	fmt.Printf("projectID from domain socket %s\n", projectID)

	tok, err := mclient.Get("instance/service-accounts/default/token")
	if err != nil {
		panic(err)
	}
	//fmt.Printf("Token %s\n", tok)

	var ret oauth2.Token
	err = json.Unmarshal([]byte(tok), &ret)
	if err != nil {
		panic(err)
	}

	ts := oauth2.StaticTokenSource(&ret)

	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	var buckets []string
	it := client.Buckets(ctx, projectID)

	for {
		battrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			panic(err)
		}
		buckets = append(buckets, battrs.Name)
		fmt.Printf("Bucket: %v\n", battrs.Name)
	}
}
