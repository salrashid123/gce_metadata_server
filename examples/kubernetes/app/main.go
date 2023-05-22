package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	"google.golang.org/api/iterator"
)

// docker.io/salrashid123/simplegcsapp@sha256:d6347483a3c5cb200fbf2490e95cfcd1edd5ff79bbc9c6080d598b206e4a9ae5

var ()

const ()

func gethandler(w http.ResponseWriter, r *http.Request) {
	projectID := ""
	if metadata.OnGCE() {
		var err error
		projectID, err = metadata.ProjectID()
		if err != nil {
			fmt.Printf("Error getting projectID: %s\n", err)
			http.Error(w, fmt.Sprintf("Error getting projectID: %s\n", err), http.StatusInternalServerError)
			return
		}
	} else {
		fmt.Println("Could not detect metadata server")
		http.Error(w, fmt.Sprintf("Could not detect metadata server"), http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		fmt.Printf("Error Creating gcs client: %s\n", err)
		http.Error(w, fmt.Sprintf("Error Creating gcs client: %s\n", err), http.StatusInternalServerError)
		return
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
			fmt.Printf("Error Iterating: %s\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		buckets = append(buckets, battrs.Name)

	}
	fmt.Fprint(w, fmt.Sprintf("Number of Buckets: %d\n", len(buckets)))
}

func main() {

	r := mux.NewRouter()
	r.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err := server.ListenAndServe()

	fmt.Printf("Unable to start Server %v", err)

}
