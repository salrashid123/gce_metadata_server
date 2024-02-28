package main

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/compute/metadata"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

func main() {

	projectID := ""
	if metadata.OnGCE() {
		var err error
		projectID, err = metadata.ProjectID()
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("metadata not detected")
		return
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
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

	// get arbitrary metadata values directly
	instanceID, err := metadata.InstanceID()
	if err != nil {
		panic(err)
	}
	fmt.Printf("InstanceID %s\n", instanceID)
}
