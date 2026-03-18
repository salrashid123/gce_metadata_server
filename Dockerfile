# go1.25.1 linux/amd64
FROM --platform=$BUILDPLATFORM docker.io/golang@sha256:d7098379b7da665ab25b99795465ec320b1ca9d4addb9f77409c4827dc904211 as build

# export TAG=v3.93.0
# docker buildx create --use --platform=linux/arm64,linux/amd64 --name multi-platform-builder
# docker buildx inspect --bootstrap
# docker buildx build --platform linux/arm64,linux/amd64 -t docker.io/salrashid123/gcemetadataserver:$TAG --output type=registry --file Dockerfile .
# docker buildx build --platform linux/arm64,linux/amd64 -t docker.io/salrashid123/gcemetadataserver:$TAG --output type=docker --file Dockerfile .

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)"  -o /go/bin/gce_metadata_server cmd/main.go 
RUN chown root:root /go/bin/gce_metadata_server

# base-debian11-root
FROM gcr.io/distroless/base@sha256:74ddbf52d93fafbdd21b399271b0b4aac1babf8fa98cab59e5692e01169a1348
COPY --from=build /go/bin/gce_metadata_server /gce_metadata_server
EXPOSE 8080
ENTRYPOINT [ "/gce_metadata_server" ]
