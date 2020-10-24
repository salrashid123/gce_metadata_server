FROM golang:1.15 AS build
ENV PROJECT gce_metadata_server
WORKDIR /src/$PROJECT
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go install -a -tags netgo -ldflags=-w

FROM gcr.io/distroless/base
COPY --from=build /go/bin/gce_metadata_server /bin/gce_metadata_server
EXPOSE 8080
ENTRYPOINT [ "/bin/gce_metadata_server" ]