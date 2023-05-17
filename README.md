# GCE Metadata Server Emulator


## Background
This script acts as a GCE's internal metadata server for local testing/emulation.

It returns a live access_token that can be used directly by [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) transparently.

For example, you can use `ComputeCredentials` on your laptop:

```python
#!/usr/bin/python

import google.auth.compute_engine
import google.auth.transport.requests

creds = google.auth.compute_engine.Credentials()
request = google.auth.transport.requests.Request()
creds.refresh(request)

session = google.auth.transport.requests.AuthorizedSession(creds)
r = session.get('https://www.googleapis.com/userinfo/v2/me').json()
print(str(r))
```

 This is useful to test any script or code locally that my need to contact GCE's metadata server for custom, user-defined variables or access_tokens.

 Another usecase for this is to verify how Application Defaults will behave while running a local docker container. A local running docker container will not have access to GCE's metadata server but by bridging your container to the emulator, you are basically allowing GCP API access directly from within a container on your local workstation (vs. running the code comprising the container directly on the workstation and relying on gcloud credentials (not metadata)).


>> This is not an officially supported Google product


For more information on the request-response characteristics:
* [GCE Metadata Server](https://cloud.google.com/compute/docs/storing-retrieving-metadata)

 The script performs the following:
 * returns the `access_token` provided by either
   * the serviceAccount JSON file you specify.
   * [workload identity federation](https://cloud.google.com/iam/docs/how-to#using-workload-identity-federation) configuration
   * service account impersonation
   * statically from a provided environment variable
 * returns Google issued OpendID token (`id_token`) for the Service Account using the audience you specify
 * return custom key-value attributes
 * Identity Token document

The endpoints that are exposed are:

 ```golang
r.Handle("/computeMetadata/v1/project/project-id")
r.Handle("/computeMetadata/v1/project/numeric-project-id")
r.Handle("/computeMetadata/v1/project/attributes/{key}")
r.Handle("/computeMetadata/v1/instance/service-accounts/")
r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/")
r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}")
r.Handle("/computeMetadata/v1/instance/")
r.Handle("/")
 ```

You are free to expand on the endpoints surfaced here..pls feel free to file a PR!


 - ![images/metadata_proxy.png](images/metadata_proxy.png)


## Usage

This script runs a basic webserver and responds back as the Google Compute Engine's metadata server.  A local webserver
runs on a non-privileged port (default: 8080) and uses a `serviceAccountFile` file or environment variables return an `access_token`
and optional live project user-defined metadata.

You can run the emulator either:

1.  directly on your laptop
2.  within a docker container running locally.

### Running the metadata server directly

The following steps details how you can run the emulator on your laptop.


#### Download JSON ServiceAccount file or use impersonation

Create a GCP Service Account JSON file (you should strongly prefer using impersonation..)

```bash
export GOOGLE_PROJECT_ID=`gcloud config get-value core/project`
export GOOGLE_NUMERIC_PROJECT_ID=`gcloud projects describe $GOOGLE_PROJECT_ID --format="value(projectNumber)"`
# optional
export GOOGLE_INSTANCE_ID=8087716956832600000
export GOOGLE_INSTANCE_NAME=vm1
export GOOGLE_ZONE=us-central1-a

gcloud iam service-accounts create metadata-sa
```

You can either create a key that represents this service account and download it locally

```bash
gcloud iam service-accounts keys create metadata-sa.json --iam-account=metadata-sa@$GOOGLE_PROJECT_ID.iam.gserviceaccount.com
```

or preferably assign your user impersonation capabilities on it:

```bash
gcloud iam service-accounts \
  add-iam-policy-binding metadata-sa@$GOOGLE_PROJECT_ID.iam.gserviceaccount.com --member=user:`gcloud config get-value core/account` \
  --role=roles/iam.serviceAccountTokenCreator
```

If you intend to use the samples in the `examples/` folder, add some viewer permission to list gcs buckets (because this is what all the stuff in the `examples/` folder shows)

```bash
# note roles/storage.admin is over-permissioned...we only need storage.buckets.list on the project...
gcloud projects add-iam-policy-binding $GOOGLE_PROJECT_ID  \
     --member="serviceAccount:metadata-sa@$GOOGLE_PROJECT_ID.iam.gserviceaccount.com"  \
     --role=roles/storage.admin
```

You can assign IAM permissions now to the service account for whatever resources it may need to access

#### Run the metadata server

Using Certs

```bash
mkdir certs/
mv metadata-sa.json certs

go run main.go -logtostderr \
  -alsologtostderr -v 5 \
  -port :8080 \
  --serviceAccountFile certs/metadata-sa.json \
  --numericProjectId $GOOGLE_NUMERIC_PROJECT_ID --projectId=$GOOGLE_PROJECT_ID --zone=$GOOGLE_ZONE --instanceID=$GOOGLE_INSTANCE_ID --instanceName=$GOOGLE_INSTANCE_NAME \
  --tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform
```

or via impersonation

```bash
 go run main.go -logtostderr    -alsologtostderr -v 5   \
  -port :8080   \
  --impersonate \
  --serviceAccountEmail metadata-sa@$GOOGLE_PROJECT_ID.iam.gserviceaccount.com \
  --numericProjectId $GOOGLE_NUMERIC_PROJECT_ID --projectId=$GOOGLE_PROJECT_ID --zone=$GOOGLE_ZONE --instanceID=$GOOGLE_INSTANCE_ID --instanceName=$GOOGLE_INSTANCE_NAME \
  --tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform
```

or via [workload identity federation](https://cloud.google.com/iam/docs/how-to#using-workload-identity-federation)

```bash
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/sts-creds.json
go run main.go -logtostderr \
  -alsologtostderr -v 5 \
  -port :8080 \
  --federate \
  --serviceAccountEmail metadata-sa@$GOOGLE_PROJECT_ID.iam.gserviceaccount.com  \
  --numericProjectId $GOOGLE_NUMERIC_PROJECT_ID --projectId=$GOOGLE_PROJECT_ID --zone=$GOOGLE_ZONE --instanceID=$GOOGLE_INSTANCE_ID --instanceName=$GOOGLE_INSTANCE_NAME \
  --tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform
```

To use this mode, you must first setup the Federation and then set the environment variable pointing to the [ADC file](https://cloud.google.com/iam/docs/configuring-workload-identity-federation#aws).

for reference, see

* [Exchange Generic OIDC Credentials for GCP Credentials using GCP STS Service](https://github.com/salrashid123/gcpcompat-oidc)
* [Exchange AWS Credentials for GCP Credentials using GCP STS Service](https://github.com/salrashid123/gcpcompat-aws)

where the `sts-creds.json` file is the generated one you created.  For example using the OIDC tutorial above, it may look like

for example, if the workload federation user is mapped to

```
principal://iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/oidc-pool-1/subject/alice@domain.com
```

then that identity should have the binding to use the metadata service account:

```bash
# enable federation for principal://
gcloud iam service-accounts add-iam-policy-binding metadata-sa@$PROJECT_ID.iam.gserviceaccount.com \
    --role roles/iam.workloadIdentityUser \
    --member "principal://iam.googleapis.com/projects/$GOOGLE_NUMERIC_PROJECT_ID/locations/global/workloadIdentityPools/oidc-pool-1/subject/alice@domain.com"
```

ultimately, the `sts-creds.json` will look like (note:, the `service_account_impersonation_url` value is not present)

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/oidc-pool-1/providers/oidc-provider-1",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/tmp/oidccred.txt"
  }
}
```

where `/tmp/oidcred.txt` contains the original oidc token

or via docker

```bash
# docker.io/salrashid123/gcemetadataserver@sha256:b74a77c63c5245c668fa93315c318e51999ebe4cf2cb94128849d44e1a7209f3
docker run \
  -v `pwd`/certs/:/certs/ \
  -p 8080:8080 \
  -t salrashid123/gcemetadataserver \
  -serviceAccountFile /certs/metadata-sa.json \
  -logtostderr -alsologtostderr -v 5 \
  -port :8080 --numericProjectId $GOOGLE_NUMERIC_PROJECT_ID --projectId=$GOOGLE_PROJECT_ID --zone=$GOOGLE_ZONE --instanceID=$GOOGLE_INSTANCE_ID --instanceName=$GOOGLE_INSTANCE_NAME \
  -tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform
```

Startup

- ![images/setup_2.png](images/setup_2.png)

#### Test access to the metadata server

In a new window, run


```bash
curl -v -H 'Metadata-Flavor: Google' --connect-to metadata.google.internal:80:127.0.0.1:8080 \
   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

>
< HTTP/1.1 200 OK
< Content-Type: application/json
< Metadata-Flavor: Google
< Server: Metadata Server for VM
< X-Frame-Options: 0
< X-Xss-Protection: 0
< Date: Mon, 26 Aug 2019 21:50:09 GMT
< Content-Length: 190
<
{"access_token":"ya29.c.EltxByD8vfv2ACageADlorFHWd2ZUIgGdU-redacted","expires_in":3600,"token_type":"Bearer"}
```

#### Test Google Auth clients

GCP Auth libraries support overriding the host/port for the metadata server.  


Each language library has their own nuances so please read the sections elow


These are not documented but you can _generally_ just set the value of.

```bash
export GCE_METADATA_HOST=localhost:8080
```

and use this emulator.  The `examples/` folder shows several clients taken from [gcpsamples](https://github.com/salrashid123/gcpsamples/tree/master/auth/compute).

Remember to run `gcloud auth application-default revoke` in any new client library test to make sure your residual creds are not used.

##### [python](https://github.com/googleapis/google-auth-library-python/blob/main/google/auth/compute_engine/_metadata.py#L35-L50)

  While `google-auth-python` supports the `GCE_METADATA_HOST`, it assumes the port you are using is always `:80` which isn't the case here.

  So you have two options:  1. either run the emulator on `:80`, or use a redirect using a utility like `socat` on linux:

```bash
sudo apt-get install socat

sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:8080
```

```bash
  export GCE_METADATA_HOST=localhost
  export GCE_METADATA_IP=127.0.0.1

  virtualenv env
  source env/bin/activate
  pip3 install -r requirements.txt

  python3 main.py
```


##### [java](https://github.com/googleapis/google-auth-library-java/blob/main/oauth2_http/java/com/google/auth/oauth2/DefaultCredentialsProvider.java#L71)

```bash
   export GCE_METADATA_HOST=localhost:8080

   mvn clean install exec:java  -q
```

##### [golang](https://github.com/googleapis/google-cloud-go/blob/main/compute/metadata/metadata.go#L41-L46)
   
```bash
  export GCE_METADATA_HOST=localhost:8080

  go run main.go
```

* [nodejs](https://github.com/googleapis/gcp-metadata/blob/main/src/index.ts#L36-L37)


```bash
  export GCE_METADATA_HOST=localhost:8080

  npm i
  node app.js  
```

* [dotnet](https://github.com/googleapis/google-api-dotnet-client/blob/main/Src/Support/Google.Apis.Auth/OAuth2/GoogleAuthConsts.cs#L136)

```bash
  export GCE_METADATA_HOST=localhost:8080

  dotnet restore
  dotnet run
```

Note, `Google.Api.Gax.Platform.Instance().ProjectId` requests the full [recursive path](https://github.com/googleapis/gax-dotnet/blob/main/Google.Api.Gax/Platform.cs#LL61C69-L61C103)

   path[/computeMetadata/v1/] query[recursive=true]

- ![images/setup_5.png](images/setup_5.png)



### IDToken

The following endpoints shows how to acquire an IDToken

```bash
curl -H "Metadata-Flavor: Google" \
'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://foo.bar'
```

The `id_token` will be signed by google but issued by the service account you used
```json
{
  "alg": "RS256",
  "kid": "178ab1dc5913d929d37c23dcaa961872f8d70b68",
  "typ": "JWT"
}.
{
  "aud": "https://foo.bar",
  "azp": "metadata-sa@$PROJECT.iam.gserviceaccount.com",
  "email": "metadata-sa@PROJECT.iam.gserviceaccount.com",
  "email_verified": true,
  "exp": 1603550806,
  "iat": 1603547206,
  "iss": "https://accounts.google.com",
  "sub": "117605711420724299222"
}

```
>>> Unlike the _real_ gce metadataserver, this will **NOT** return the full identity document or license info :(`&format=[FORMAT]&licenses=[LICENSES]`)

### Run the metadata server with containers

#### Access the local emulator _from_ containers

```bash
cd examples/container
docker build -t myapp .
docker run -t --net=host -e GCE_METADATA_HOST=localhost:8080  myapp
```
You may need to drop existing firewall rules and then restart the docker daemon to prevent conflicts or overrides.


> *NOTE:*   using --net=host is only recommended for testing; For more information see:

* [Docker Networking](https://docs.docker.com/v1.8/articles/networking/#container-networking)
* [Embedded DNS server in user-defined networks](https://docs.docker.com/engine/userguide/networking/configure-dns/#/embedded-dns-server-in-user-defined-networks)

#### Running as Kubernetes Service

You can run the emulator as a kubernetes service but you cannot bind the link local address `169.254.169.254` with a k8s service. see [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors):

_"The endpoint IPs must not be: loopback (127.0.0.0/8 for IPv4, ::1/128 for IPv6), or link-local (169.254.0.0/16 and 224.0.0.0/24 for IPv4, fe80::/64 for IPv6)."_

So. you'll need to specify a kubernetes `Service` address by injecting `GCE_METADATA_HOST` environment variable to the containers 

### Using static environment variables

If you do not have access to certificate file or would like to specify **static** token values via env-var, the metadata server supports the following environment variables as substitutions.  Once you set these environment variables, the service will not look for anything using the service Account JSON file (even if specified)

```bash
export GOOGLE_PROJECT_ID=`gcloud config get-value core/project`
export GOOGLE_NUMERIC_PROJECT_ID=`gcloud projects describe $GOOGLE_PROJECT_ID --format="value(projectNumber)"`
export GOOGLE_ACCESS_TOKEN="some_static_token"
export GOOGLE_ID_TOKEN="some_id_token"
```

for example,

```bash
go run main.go -logtostderr  \
   -alsologtostderr -v 5 \
   -port :8080  \
   --tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform
```

or

```bash
docker run \
  -p 8080:8080 \
  -e GOOGLE_ACCESS_TOKEN=$GOOGLE_ACCESS_TOKEN \
  -e GOOGLE_NUMERIC_PROJECT_ID=$GOOGLE_NUMERIC_PROJECT_ID \
  -e GOOGLE_PROJECT_ID=$GOOGLE_PROJECT_ID \
  -e GOOGLE_ACCOUNT_EMAIL=$GOOGLE_ACCOUNT_EMAIL \
  -e GOOGLE_ID_TOKEN=$GOOGLE_ID_TOKEN \  
  -t salrashid123/gcemetadataserver \
  -port :8080 \
  -tokenScopes https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform \
  -logtostderr -alsologtostderr -v 5

```

```bash
curl -v -H "Metadata-Flavor: Google" --connect-to metadata.google.internal:80:127.0.0.1:8080 http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

some_static_token
```

#### Extending the sample
You can extend this sample for any arbitrary metadata you are interested in emulating (eg, disks, hostname, etc).
Simply add the routes to the webserver and handle the responses accordingly.  It is recommended to view the request-response format directly on the metadata server to compare against.


### TODO

1.  Directory Browsing

Instead of explicitly setting routes, use the local filesystem to return the structure for non-dynamic content or attributes.  In this way, the metadata server just returns the directory and files that mimics the metadata server structure.

eg: create a directory structure similar to:

```
./static/
    0.1/
    computeMetadata/
      v1beta1/
      v1/
        instance/
        oslogin/
        project/
```


```golang
r.Handle("/", checkMetadataHeaders(http.FileServer(http.Dir("./static"))))
```
Which currently returns HTML content as well as`Content-Type: text/html; charset=utf-8`, the metadata server new-line text  as `Content-Type: application/text`

TODO: figure out how to return text payload similar to the metadata server

```bash
$ curl -H "Metadata-Flavor: Google" --connect-to metadata.google.internal:80:127.0.0.1:8080  -v http://metadata.google.internal/
*   Trying 169.254.169.254...
* TCP_NODELAY set
* Connected to metadata.google.internal (169.254.169.254) port 80 (#0)
> GET / HTTP/1.1
> Host: metadata.google.internal
> User-Agent: curl/7.52.1
> Accept: */*
> Metadata-Flavor: Google
>
< HTTP/1.1 200 OK
< Metadata-Flavor: Google
< Content-Type: application/text
< Date: Mon, 26 Aug 2019 17:08:17 GMT
< Server: Metadata Server for VM
< Content-Length: 22
< X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
<
0.1/
computeMetadata/
```

```bash


$ curl -H "Metadata-Flavor: Google" --connect-to metadata.google.internal:80:127.0.0.1:8080 -s http://metadata.google.internal/computeMetadata/v1/instance
/computeMetadata/v1/instance/

$ curl -H "Metadata-Flavor: Google" --connect-to metadata.google.internal:80:127.0.0.1:8080 -s http://metadata.google.internal/computeMetadata/v1/instance/
attributes/
cpu-platform
description
disks/
guest-attributes/
hostname
id
image
licenses/
machine-type
maintenance-event
name
network-interfaces/
preempted
remaining-cpu-time
scheduling/
service-accounts/
tags
virtual-clock/
zone
```
