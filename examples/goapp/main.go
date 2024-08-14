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
	ctx := context.Background()

	if metadata.OnGCE() {
		var err error
		projectID, err = metadata.ProjectIDWithContext(ctx)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("metadata not detected")
		return
	}

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
	instanceID, err := metadata.InstanceIDWithContext(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("InstanceID %s\n", instanceID)
}
