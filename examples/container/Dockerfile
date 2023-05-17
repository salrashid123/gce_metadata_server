# go1.19.8 linux/amd64
FROM docker.io/golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -buildvcs=false  -o /go/bin/server


RUN chown root:root /go/bin/server && \
  chown -R root:root /go/src/app

# base-debian11-root
FROM gcr.io/distroless/base-debian11@sha256:df13a91fd415eb192a75e2ef7eacf3bb5877bb05ce93064b91b83feef5431f37
COPY --from=build /go/bin/server /server
ENTRYPOINT [ "/server" ]