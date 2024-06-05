# go1.22.2 linux/amd64
FROM docker.io/golang@sha256:d5302d40dc5fbbf38ec472d1848a9d2391a13f93293a6a5b0b87c99dc0eaa6ae as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false  -o /go/bin/gce_metadata_server cmd/main.go 
RUN chown root:root /go/bin/gce_metadata_server

# base-debian11-root
FROM gcr.io/distroless/base@sha256:b31a6e02605827e77b7ebb82a0ac9669ec51091edd62c2c076175e05556f4ab9
COPY --from=build /go/bin/gce_metadata_server /gce_metadata_server
EXPOSE 8080
ENTRYPOINT [ "/gce_metadata_server" ]