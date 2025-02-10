# go1.23.4 linux/amd64
FROM --platform=$BUILDPLATFORM docker.io/golang@sha256:9820aca42262f58451f006de3213055974b36f24b31508c1baa73c967fcecb99 as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false  -o /go/bin/gce_metadata_server cmd/main.go 
RUN chown root:root /go/bin/gce_metadata_server

# base-debian11-root
FROM gcr.io/distroless/base@sha256:74ddbf52d93fafbdd21b399271b0b4aac1babf8fa98cab59e5692e01169a1348
COPY --from=build /go/bin/gce_metadata_server /gce_metadata_server
EXPOSE 8080
ENTRYPOINT [ "/gce_metadata_server" ]
