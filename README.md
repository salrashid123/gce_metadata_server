# GCE Metadata Server Emulator

This script acts as a GCE's internal metadata server.

It returns a live `access_token` that can be used directly by [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) from any SDK library or return any GCE metadata key-value pairs and attributes.

For example, you can call `ADC` using default credentials or specifically with `ComputeCredentials` and also recall any GCE project or instance attribute.

To use, first run the emulator:

```bash
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 \
  --serviceAccountFile certs/metadata-sa.json 
```

Note the credentials for the server can be sourced from a service account key, workload federation, `Trusted Platform Module (TPM)` or statically provided as environment variable.  The example above uses a key.

Then in a new window, export some env vars google SDK's under

```bash
export GCE_METADATA_HOST=localhost:8080
export GCE_METADATA_IP=127.0.0.1:8080
```

and run any application using ADC:

```python
#!/usr/bin/python

from google.cloud import storage
import google.auth
import google.auth.compute_engine
import google.auth.transport.requests
from google.auth.compute_engine import _metadata


## with ADC metadata server

credentials, project = google.auth.default()    
client = storage.Client(credentials=credentials)
buckets = client.list_buckets()
for bkt in buckets:
  print(bkt)


## as compute credential

creds = google.auth.compute_engine.Credentials()
session = google.auth.transport.requests.AuthorizedSession(creds)
r = session.get('https://www.googleapis.com/userinfo/v2/me').json()
print(str(r))


## get arbitrary metadata values directly 

request = google.auth.transport.requests.Request()
print(_metadata.get_project_id(request))
print(_metadata.get(request,"instance/id"))
```

You can also launch the metadata server directly from your app or use in unit tests:

```golang
package main

import (
  	mds "github.com/salrashid123/gce_metadata_server"    
)

func TestSomething(t *testing.T) {

  // use any any credentials (static, real or fake)
  creds, _ := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")

  serverConfig := &mds.ServerConfig{
		BindInterface: "127.0.0.1",
		Port:          ":8080",
  }

  claims := &mds.Claims{
		ComputeMetadata: mds.ComputeMetadata{
			V1: mds.V1{
				Project: mds.Project{
					ProjectID: "some_project_id",
				},
			},
		},
  }

  f, _ := mds.NewMetadataServer(ctx, serverConfig, creds, claims)

  err = f.Start()
  defer f.Shutdown()

  // optionally set a env var google sdk libraries understand
  // t.Setenv("GCE_METADATA_HOST", "127.0.0.1:8080")
  // do tests here, eg with "cloud.google.com/go/compute/metadata"
  // mid, _ := metadata.ProjectID()

  // or call it directly
  // client := &http.Client{}
  // req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/computeMetadata/v1/project/project-id", nil)
  // req.Header.Set("Metadata-Flavor", "Google")
  // res, _ := client.Do(req)  
}
```

The metadata server supports additional endpoints that simulate other instance attributes normally only visible inside a GCE instance like `instance_id`, `disks`, `network-interfaces` and so on.

For more information on the request-response characteristics:
* [GCE Metadata Server](https://cloud.google.com/compute/docs/storing-retrieving-metadata)
* [Predefined metadata keys](https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys)
* [Set and remove custom metadata](https://cloud.google.com/compute/docs/metadata/setting-custom-metadata)

 The script performs the following:
 * returns the `access_token` and `id_token` provided by either
   * the serviceAccount JSON file you specify.
   * [workload identity federation](https://cloud.google.com/iam/docs/how-to#using-workload-identity-federation) configuration
   * service account impersonation
   * statically from a provided environment variable
   * service account RSA key on `HSM` or `Trusted Platform Module (TPM)`
 * return project attributes (`project_id`, `numeric-project-id`)
 * return instance attributes (`instance-id`, `tags`, `network-interfaces`, `disks`)

You can run the emulator:

1.  directly on your laptop
2.  within a docker container locally.
3.  as a kubernetes service
4.  with some difficulty, bound to the link-local address (`169.254.169.254`)
5.  within unit tests

The endpoints that are exposed are:

 ```golang
r.Handle("/computeMetadata/v1/project/project-id")
r.Handle("/computeMetadata/v1/project/numeric-project-id")
r.Handle("/computeMetadata/v1/project/attributes/{key}")

r.Handle("/computeMetadata/v1/instance/service-accounts/")
r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/")
r.Handle("/computeMetadata/v1/instance/service-accounts/{acct}/{key}")
r.Handle("/computeMetadata/v1/instance/network-interfaces/{index}/access-configs/{index2}/{key}")
r.Handle("/computeMetadata/v1/instance/attributes/{key}")
r.Handle("/computeMetadata/v1/instance/{key}")
r.Handle("/")
```

---

>> This is not an officially supported Google product

---

* [Configuration](#configuration)
  - [With JSON ServiceAccount file](#with-json-serviceaccount-file)
  - [With Impersonation](#with-impersonation)
  - [With Workload Federation](#with-workload-federation)
  - [With TPM](#with-trusted-platform-module-tpm)
* [Usage](#usage)      
* [Startup](#startup)
  - [AccessToken](#accesstoken)
  - [IDToken](#idtoken)
  - [Attributes](#attributes)
* [Using Google Auth clients](#using-google-auth-clients)
  - [python](#python)
  - [java](#java)
  - [golang](#golang)
  - [nodejs](#nodejs) 
  - [dotnet](#dotnet)  
  - [gcloud](#gcloud)      
* [Other Runtimes](#other-runtimes)
    - [Run emulator as container](#run-emulator-as-container)    
    - [Run with containers](#run-with-containers)
    - [Running as Kubernetes Service](#running-as-kubernetes-service)
    - [Static environment variables](#static-environment-variables)
- [Dynamic Configuration File Updates](#dynamic-configuration-file-updates)
- [ETag](#etag)    
- [Extending the sample](#extending-the-sample)
- [Using link-local address](#using-link-local-address)
- [Using domain sockets](#using-domain-sockets)
- [Building with Bazel](#building-with-bazel)
- [Building with Kaniko](#building-with-kaniko)
* [GCE mTLS](#gce-mtls)
* [Envoy Authentication Filter](#envoy-authentication-filter)  
* [Metrics](#metrics)
* [Testing](#testing)

---

Note, the real metadata server has some additional query parameters which are either partially or not implemented:

- [recursive=true](https://cloud.google.com/compute/docs/metadata/querying-metadata#aggcontents) partially implemented
- [?alt=json](https://cloud.google.com/compute/docs/metadata/querying-metadata#format_query_output) not implemented
- [?wait_for_change=true](https://cloud.google.com/compute/docs/metadata/querying-metadata#waitforchange) not implemented

You are free to expand on the endpoints surfaced here..pls feel free to file a PR!

 ![images/metadata_proxy.png](images/metadata_proxy.png)

---

## Configuration 

The metadata server reads a configuration file for static values and uses a service account for dynamically getting `access_token` and `id_token`.

The basic config file format roughly maps the uri path of the actual metadata server and the emulator uses these values to populate responses.

For example, the `instance_id`, `project_id`, `serviceAccountEmail` and other files are read from the values here, for example, see [config.json](config.json):

```json
{
  "computeMetadata": {
    "v1": {
      "instance": {
        "id": 5775171277418378000,
        "serviceAccounts": {
          "default": {
            "aliases": [
              "default"
            ],
            "email": "metadata-sa@your-project.iam.gserviceaccount.com",
            "scopes": [
              "https://www.googleapis.com/auth/cloud-platform",
              "https://www.googleapis.com/auth/userinfo.email"
            ]
          }
        }
      },
      "oslogin": {},
      "project": {
        "numericProjectId": 708288290784,
        "projectId": "your-project"
      }
    }
  }
}
```

The field are basically a JSON representation of what the real metadata server returns recursively

```bash
$ curl -v -H 'Metadata-Flavor: Google' http://metadata/computeMetadata/v1/?recursive=true | jq '.'
```

Any requests for an `access_token` or an `id_token` are dynamically generated using the credential provided.  The scopes for any token uses the values set in the config file

## Usage

The following steps details how you can run the emulator on your laptop.

You can either build from source:

```bash
go build -o gce_metadata_server cmd/main.go
```

Or download an appropriate binary from the [Releases](https://github.com/salrashid123/gce_metadata_server/releases) page

You can set the following options on usage:

| Option | Description |
|:------------|-------------|
| **`-configFile`** | configuration File (default: `config.json`) |
| **`-interface`** | interface to bind to (default: `127.0.0.1`) |
| **`-port`** | port to listen on (default: `:8080`) |
| **`-serviceAccountFile`** | path to serviceAccount json Key file |
| **`-impersonate`** | use impersonation |
| **`-federate`** | use workload identity federation |
| **`-tpm`** | use TPM |
| **`-persistentHandle`** | TPM persistentHandle (default: none) |
| **`-tpmKeyFile`** | TPM Encrypted private key (default: none) |
| **`-tpmPath`** |"Path to the TPM device (character device or a Unix socket). (default: `/dev/tpmrm0`)" |
| **`-parentPass`** | TPM Parent key password (default: "") |
| **`-keyPass`** | TPM key password (default: "") |
| **`-pcrs`** | TPM PCR values the key is bound to (comma separated pcrs in ascending order) |
| **`-sessionEncryptionName`** | hex encoded TPM object 'name' to use with an encrypted session |
| **`-domainsocket`** | listen on unix socket |
| **`GOOGLE_PROJECT_ID`** | static environment variable for PROJECT_ID to return |
| **`GOOGLE_NUMERIC_PROJECT_ID`** | static environment variable for the numeric project id to return |
| **`GOOGLE_ACCESS_TOKEN`** | static environment variable for access_token to return |
| **`GOOGLE_ID_TOKEN`** | static environment variable for id_token to return |
| **`-metricsEnabled`** | Enable prometheus metrics endpoint (default: false) |
| **`-metricsInterface`** | Prometheus metrics interface (default: 127.0.0.1) |
| **`-metricsPort`** | Prometheus metrics port (default: 9000) |
| **`-metricsPath`** | Prometheus metrics path (default: /metrics) |
| **`-usemTLS`** | Start server with mtls (default: false) |
| **`-rootCAmTLS`** | Root CA for mtls client validation (default: `certs/root.crt`) |
| **`-serverCert`** | Server certificate for mtls (default: `certs/server.crt`) |
| **`-serverKey`** | Server key for mtls (default: `certs/server.key`) |

### With JSON ServiceAccount file

Create a GCP Service Account JSON file (you should strongly prefer using impersonation..)

```bash
export PROJECT_ID=`gcloud config get-value core/project`
gcloud iam service-accounts create metadata-sa
```

You can either create a key that represents this service account and download it locally

```bash
gcloud iam service-accounts keys create metadata-sa.json \
   --iam-account=metadata-sa@$PROJECT_ID.iam.gserviceaccount.com
```

or preferably assign your user impersonation capabilities on it (see section below)

You can assign IAM permissions now to the service account for whatever resources it may need to access and then run:

```bash
mkdir certs/
mv metadata-sa.json certs

./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 \
  --serviceAccountFile certs/metadata-sa.json 
```

### With Impersonation

If you use impersonation, the `serviceAccountEmail` and `scopes` are taken from the config file's default service account.

First setup impersonation for your user account:

```bash
gcloud iam service-accounts \
  add-iam-policy-binding metadata-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --member=user:`gcloud config get-value core/account` \
  --role=roles/iam.serviceAccountTokenCreator
```

then,

```bash
./gce_metadata_server -logtostderr \
     -alsologtostderr -v 5  -port :8080 \
     --impersonate --configFile=config.json
```

### With Workload Federation

For [workload identity federation](https://cloud.google.com/iam/docs/how-to#using-workload-identity-federation), you need to reference the credentials.json file as usual:

then just use the default env-var and run:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/sts-creds.json
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 --federate 
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

### With Trusted Platform Module (TPM)

If the service account private key is bound inside a `Trusted Platform Module (TPM)`, the metadata server can use that key to issue an `access_token` or an `id_token`

>> Note: not all platforms supports this mode.  The underlying go-tpm library is only supported on a few of the targets (`linux/darwin + amd64,arm64`).  If you need support for other platforms, one option is to comment the sections for the TPM, remove the library bindings and compile.

Before using this mode, the key _must be_ sealed into the TPM and surfaced as a `persistentHandle`.  This can be done in a number of ways described [here](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource): 

Basically, you can either

- `A` download a Google ServiceAccount's json file and embed the private part to the TPM. [example](https://github.com/salrashid123/oauth2/blob/master/README.md#a-import-service-account-json-to-tpm)
- `B` Generate a Key _on the TPM_ and then import the public part to GCP. [example](https://github.com/salrashid123/oauth2/blob/master/README.md#b-generate-key-on-tpm-and-export-public-x509-certificate-to-gcp)
- `C` remote seal the service accounts RSA Private key, encrypt it with TPM's Endorsement Key and load it securely inside the TPM. [example](https://gist.github.com/salrashid123/9e4a0328fd8c84374ace78c76a1e34cb)

`A` is the easiest for a demo

`B` is the most secure

`C` allows for multiple TPMs to use the same key 

Anyway, once the RSA key is present as a handle, start the metadata server using the `--tpm` flag and set the `--persistentHandle=` value.

TPM based tokens derives the serivceAccount email from the configuration file.   You must first edit `config.json` and set the value of `Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email`.

For a full example with `A`, you'll need a serviceAccount key file first which you'll embed into the TPM.

Using `tpm2_tools`:

```bash
## prepare they key
## extract just the private key from the json keyfile

cat tpm-svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -in /tmp/f.json -out /tmp/key_rsa.pem 

## create the primary
### the specific primary here happens to be the h2 template described later on but you are free to define any template and policy

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
 
tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_flushcontext -t

## either persist the key to a handle
tpm2_evictcontrol -C o -c key.ctx 0x81010002

### or as PEM format file
## to create a TPM PEM formatted file,
## either use https://github.com/salrashid123/tpm2genkey
## or just
tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o private.pem

## this formats it as TPM-encrypted PEM:
cat private.pem 
-----BEGIN TSS2 PRIVATE KEY-----
MIICNQYGZ4EFCgEDoAMBAf8CBEAAAAEEggEaARgAAQALAAQAQAAAABAAFAALCAAA
AQABAQDqKVruwZ6amTB9OFXwOqNkl7Zaxh0jD1AXbnD9uvnk0z18tGOHxzsP6lsm
LJ8ywnMkomdbDP78dZlHEC3sn/7ustRUTwHb9UV/gc875gMJ0qsrbRajsH1J7tQB
S4ezEf8MKoBi9ogUx7g21z7cytiK46nr08J3yyZHvXVuCklncXBD8TM9ZlHVdDeM
ICMOzXg6d0fL0UvujGPSIEYnqbmY4DlpI0RudMAsOtActbo7Dq7xuiSBcW9slxxS
e18mO6/3IJANKVlHkynpjTEkzzchKR5brCoteukcLhSPTlSNmkvzBOXbDTyRhrrs
8HEyufQGc4MGLjStpTFNsOHy1xqnBIIBAAD+ACDtgAG7hcbIVsgW1JHzyZcWQRdv
TntWp4sacW0ltVvMLwAQvxAAj4Y0E9FyZesU/urN7896vACshaTw5lNuV7hr9ZKr
oWjGMcFo9r+H4OvshONF/GTc3ggp7UlbBo5+V5UlcQrUbk3dSGEstVgA+Wf4upoM
Q9jCmwuljqFRG7afs6js5CWfXn+z6bKIewa9mTIkjXa7GhDCHBTRO5LVn68L5dFS
0ddxx3FNZ7W4S+Md8jG19TU2oagKyrH4cXObRL1dlWSiDB0U62LHIzQcdKUENv4Y
2GDcvBxUtXWp/kBhZ5EaNOoH31njN1Pi8bZQE86j/JDNuC3i4TKdGCA=
-----END TSS2 PRIVATE KEY-----
```

After that, run

```bash
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 \
  --tpm --persistentHandle=0x81010002 
```

or with files

```bash
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 \
  --tpm --keyfile=/path/to/private.pem 
```

The TPM based credentials imports a JWT generator library to perform the oauth and id_token exchanges: 

* [salrashid123/golang-jwt-tpm](https://github.com/salrashid123/golang-jwt-tpm)
* [salrashid123/oauth2](https://github.com/salrashid123/oauth2)

If the TPM based key is restricted through a PCR policy, you will need to supply the list of PCRs its bound to using the `--pcrs` flag: (eg `--pcrs=2,3,23`).  See examples [here](https://github.com/salrashid123/gcp-adc-tpm?tab=readme-ov-file#pcr-policy)

Note that if you are using PCR policy, the metadata server cache's the credential values until it expires (which is typically an hour). If you enable a PCR policy and then change it to invalidate the TPM-based key's usage, the server will return the same token until it needs to referesh it.

If you want to enable [TPM Encrypted sessions](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), you should provide the "name" of a trusted key on the TPM for each call.

A trusted key can be the EK Key. You can get the name using `tpm2_tools`:

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o ek.pem -n name.bin -f pem -Q
xxd -p -c 100 name.bin 
  000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```

Then use the hex value returned in the `--tpm-session-encrypt-with-name=` argument.

For example:

```bash
   --tpm-session-encrypt-with-name=000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```

You can also derive the "name" from a public key of a known template.  see [go-tpm.tpm2_get_name](https://github.com/salrashid123/tpm2/tree/master/tpm2_get_name)

A TODO enhancement could be to add on support for `PKCS-11` systems:  eg [salrashid123/golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11)

also see:

* [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
* [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)

## Startup

Use any of the credential initializations described above and on startup, you will see something like:

```bash
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 \
  --serviceAccountFile certs/metadata-sa.json 
```

![images/setup_2.png](images/setup_2.png)

### AccessToken

In a new window, run

```bash
curl -s -H 'Metadata-Flavor: Google' --connect-to metadata.google.internal:80:127.0.0.1:8080 \
   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

{
  "access_token": "ya29.c.EltxByD8vfv2ACageADlorFHWd2ZUIgGdU-redacted",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

Please note the scopes used for this token is read in from the declared values in the config file.

To mention, if the only use for this is to acquire credentials for use with a GCP SDK, consider any of the "process credential sources":

* `golang`: [https://github.com/salrashid123/gcp_process_credentials_go](https://github.com/salrashid123/gcp_process_credentials_go)
* `python`: [https://github.com/salrashid123/gcp_process_credentials_py](https://github.com/salrashid123/gcp_process_credentials_py)
* `java`: [https://github.com/salrashid123/gcp_process_credentials_java](https://github.com/salrashid123/gcp_process_credentials_java)
* `node`: [https://github.com/salrashid123/gcp_process_credentials_node](https://github.com/salrashid123/gcp_process_credentials_node)

or if using go, oauth2 directly from a Trusted Platform Module:

*[GCP TPM based TokenSource](https://github.com/salrashid123/oauth2#usage-tpmtokensource)

### IDToken

The following endpoints shows how to acquire an IDToken

```bash
curl -H "Metadata-Flavor: Google" --connect-to metadata.google.internal:80:127.0.0.1:8080 \
'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://foo.bar'
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

*Important:* To get `id_tokens`, you must edit `config.json` and set the value of

- `Claims.ComputeMetadata.V1.Instance.ServiceAccounts["default"].Email`

to the value present for the credentials you are using (eg set it to `metadata-sa@$PROJECT.iam.gserviceaccount.com` (substituting in value for your real $PROJECT))

>>> Unlike the _real_ gce metadataserver, this will **NOT** return the full identity document or license info :(`&format=[FORMAT]&licenses=[LICENSES]`)


### Attributes

To acquire instance or project attributes, simply call the endpoint:

For example, to get the instance id:

```bash
curl -s -H 'Metadata-Flavor: Google' --connect-to metadata.google.internal:80:127.0.0.1:8080 \
      http://metadata.google.internal/computeMetadata/v1/instance/id

5775171277418378000
```

## Using Google Auth clients

GCP Auth libraries support overriding the host/port for the metadata server.  


Each language library has their own nuances so please read the sections elow


These are not documented but you can _generally_ just set the value of.

If you intend to use the samples in the `examples/` folder, add some viewer permission to list gcs buckets (because this is what all the stuff in the `examples/` folder shows)

```bash
# note roles/storage.admin is over-permissioned...we only need storage.buckets.list on the project...
gcloud projects add-iam-policy-binding $PROJECT_ID  \
     --member="serviceAccount:metadata-sa@$PROJECT_ID.iam.gserviceaccount.com"  \
     --role=roles/storage.admin
```

then usually just,

```bash
export GCE_METADATA_HOST=localhost:8080
```

and use this emulator.  The `examples/` folder shows several clients taken from [gcpsamples](https://github.com/salrashid123/gcpsamples/tree/master/auth/compute).

Remember to run `gcloud auth application-default revoke` in any new client library test to make sure your residual creds are not used.

##### [python](https://github.com/googleapis/google-auth-library-python/blob/main/google/auth/compute_engine/_metadata.py#L35-L50)

see [examples/pyapp](examples/pyapp/)

```bash
  export GCE_METADATA_HOST=localhost:8080
  export GCE_METADATA_IP=127.0.0.1:8080

  virtualenv env
  source env/bin/activate
  pip3 install -r requirements.txt

  python3 main.py
```

Unlike the other language SDK's, for python we need to set `GCE_METADATA_IP` (see [google-auth-library-python #1505](https://github.com/googleapis/google-auth-library-python/issues/1505)).

##### [java](https://github.com/googleapis/google-auth-library-java/blob/main/oauth2_http/java/com/google/auth/oauth2/DefaultCredentialsProvider.java#L71)

see [examples/javaapp](examples/javapp/)

```bash
   export GCE_METADATA_HOST=localhost:8080

   mvn clean install exec:java  -q
```

##### [golang](https://github.com/googleapis/google-cloud-go/blob/main/compute/metadata/metadata.go#L41-L46)

see [examples/goapp](examples/goapp/)

```bash
  export GCE_METADATA_HOST=localhost:8080

  go run main.go
```

##### [nodejs](https://github.com/googleapis/gcp-metadata/blob/main/src/index.ts#L36-L37)

see [examples/nodeapp](examples/nodeapp/)

```bash
  export GCE_METADATA_HOST=localhost:8080

  npm i
  node app.js  
```

##### [dotnet](https://github.com/googleapis/google-api-dotnet-client/blob/main/Src/Support/Google.Apis.Auth/OAuth2/GoogleAuthConsts.cs#L136)

see [examples/dotnet](examples/dotnet/)

```bash
  export GCE_METADATA_HOST=localhost:8080

  dotnet restore
  dotnet run
```

Note, `Google.Api.Gax.Platform.Instance().ProjectId` requests the full [recursive path](https://github.com/googleapis/gax-dotnet/blob/main/Google.Api.Gax/Platform.cs#LL61C69-L61C103)


#### gcloud

```bash
export GCE_METADATA_ROOT=localhost:8080

$ gcloud config list
[component_manager]
disable_update_check = True
[core]
account = metadata-sa@mineral-minutia-820.iam.gserviceaccount.com
project = mineral-minutia-820
```

`gcloud` uses a different env-var but if you want to use `gcloud auth application-default print-access-token`, you need to _also_ use `GCE_METADATA_HOST` and `GCE_METADATA_IP`


## Other Runtimes

### Run emulator as container

This emulator is also published as a release-tagged container to dockerhub:

* [https://hub.docker.com/r/salrashid123/gcemetadataserver](https://hub.docker.com/r/salrashid123/gcemetadataserver)

You can verify the image were signed by the repo owner if you really want to (see section below). 

### Run with containers

To access the local emulator _from_ containers

```bash
cd examples/container
docker build -t myapp .
docker run -t --net=host -e GCE_METADATA_HOST=localhost:8080  myapp
```

then run the emulator standalone or as a container itself:

```bash
docker run \
  -v `pwd`/certs/:/certs/ \
  -v `pwd`/config.json:/config.json \
  -p 8080:8080 \
  -t salrashid123/gcemetadataserver  \
      -serviceAccountFile /certs/metadata-sa.json \
      --configFile=/config.json \
      -logtostderr -alsologtostderr -v 5 \
      -interface 0.0.0.0 -port :8080
```

### Running as Kubernetes Service

You can run the emulator as a kubernetes `Service`  and reference it from other pods address by injecting `GCE_METADATA_HOST` environment variable to the containers:

If you want test this with `minikube` locally,

```bash
## first create the base64encoded form of the service account key
cat certs/metadata-sa.json | base64  --wrap=0 -
cd examples/kubernetes
```

then edit metadata.yaml and replace the values: 

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gcp-svc-account
type: Opaque
data:
  metadata-sa.json: "replace with contents of cat certs/metadata-sa.json | base64  --wrap=0 -"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mds-config
data:
  config.json: |
     "replace with contents of config.json"  
```

Finally test

```bash
minikube start
kubectl apply -f .
minikube dashboard --url
minikube service app-service --url

$ curl -s `minikube service app-service --url`

Number of Buckets: 62
```

>> needless to say, the metadata Service should be accessed only form authorized pods

### Dynamic Configuration File Updates

Changes to the claims configuration file (`--configFile=`) while the metadata server is running will automatically update values returned by the server.

On startup, the metadata server sets a file listener on that config file and any updates to the values will propagate back to the server without requiring a restart.

### ETag

GCE metadata servers return values with [ETag](https://cloud.google.com/compute/docs/metadata/querying-metadata#etags) headers.  The ETag is used to check if a specific attribute or value has changed.  

This metadata server will hash the value for the body to return and use that as the ETag.  If you update the configuration file with new attributes or values, the ETag for that node will change.  The `ETag` header key is returned in non-canonical format.

Note `wait-for-change` value is not supported currently so while you can poll for etag changes, you cannot listen and hold.

Finally, since the etag is just a hash of the node, if you change a value then back again, the same etag will get returned for that node. 

### Static environment variables

If you do not have access to certificate file or would like to specify **static** token values via env-var, the metadata server supports the following environment variables as substitutions.  Once you set these environment variables, the service will not look for anything using the service Account JSON file (even if specified)

```bash
export GOOGLE_PROJECT_ID=`gcloud config get-value core/project`
export GOOGLE_NUMERIC_PROJECT_ID=`gcloud projects describe $GOOGLE_PROJECT_ID --format="value(projectNumber)"`
export GOOGLE_ACCESS_TOKEN="some_static_token"
export GOOGLE_ID_TOKEN="some_id_token"
export GOOGLE_ACCOUNT_EMAIL="metadata-sa@PROJECT.iam.gserviceaccount.com"
```

for example you can use those env vars and specify a fake svc account json key file (fake since its not actually even used)

```bash
./gce_metadata_server -logtostderr  \
   -alsologtostderr -v 5 \
   -port :8080 --configFile=`pwd`/config.json  --serviceAccountFile=certs/fake_sa.json
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
  -v `pwd`/config.json:/config.json \
  -v `pwd`/certs/fake_sa.json:/certs/fake_sa.json \
  -t salrashid123/gcemetadataserver \
  -port :8080 --configFile=/config.json --serviceAccountFile=/certs/fake_sa.json \
  --interface=0.0.0.0 -logtostderr -alsologtostderr -v 5
```

```bash
curl -v -H "Metadata-Flavor: Google" \
  --connect-to metadata.google.internal:80:127.0.0.1:8080 \
   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

some_static_token
```

#### Extending the sample

You can extend this sample for any arbitrary metadata you are interested in emulating (eg, disks, hostname, etc).
Simply add the routes to the webserver and handle the responses accordingly.  It is recommended to view the request-response format directly on the metadata server to compare against.

#### Using Link-Local address

GCE's metadata server's IP address on GCE is a special link-local address: `169.254.169.254`.  Certain application default credential libraries for google cloud _may_ reference the metadata server by IP address so we're adding this in.

If you use the link-local address, do *not* set `GCE_METADATA_HOST`

if you really want to use the link local address, you have two options:  use `iptables` or `socat`.  Both require some setup as root

first create `/etc/hosts`:

```bash
169.254.169.254       metadata metadata.google.internal
```

for `socat`

create an IP alias:

```bash
sudo ifconfig lo:0 169.254.169.254 up
```

relay using `socat`:

```bash
sudo apt-get install socat

sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:8080
```

for  `iptables`

configure iptables:

```bash
iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DNAT --to-destination 127.0.0.1:8080
```

Finally, access the endpoint via IP or alias over port `:80`

```bash
curl -v -H 'Metadata-Flavor: Google' \
     http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

If you don't mind running the program on port `:80` directly, you can skip the socat and iptables and simply start the emulator to on the link address (`-port :80 --interface=169.254.169.254`)  after setting the `/etc/hosts` variable.

#### Using Domain Sockets

You can also start the metadata server to listen on a [unix domain socket](https://en.wikipedia.org/wiki/Unix_domain_socket).

To do this, simply specify `--domainsocket=` flag pointing to some file (eg ` --domainsocket=/tmp/metadata.sock`).  Once you do this, all tcp listeners will be disabled.

To access using curl, use its `--unix-socket` flag

```bash
curl -v --unix-socket /tmp/metadata.sock \
 -H 'Metadata-Flavor: Google' \
   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

While it works fine with things like curl, the main issue with using domain sockets is that the default `GCE_METADATA_HOST` variable just [listens on tcp](https://github.com/googleapis/google-cloud-go/blob/3a4ec650177be4d48aa7a0b8a22ea2b211522d80/compute/metadata/metadata.go#L308)  

And its awkward to do all the overrides for a GCP SDK to "just use" a domain socket...

If you really wanted to use unix sockets, you can find an example of how to do this in the `examples/goapp_unix` folder

anyway, just for fun, you can pipe a tcp socket to domain using `socat` (or vice versa) but TBH, you're now back to where you started with a tcp listener..

```bash
socat TCP-LISTEN:8080,fork,reuseaddr UNIX-CONNECT:/tmp/metadata.sock
```

#### Building with Bazel

If you want to build the server using bazel (eg, [deterministic](https://github.com/salrashid123/go-grpc-bazel-docker)),

```bash
# $ bazel version
#   Build label: 6.2.1

## generate dependencies
# bazel run :gazelle -- update-repos -from_file=go.mod -prune=true -to_macro=repositories.bzl%go_repositories

## run
bazel run cmd:main -- --configFile=`pwd`/config.json   -alsologtostderr -v 5 -port :8080 --serviceAccountFile=`pwd`/certs/metadata-sa.json 

## to build the image
bazel build cmd:tar-oci-index
  ## oci image at bazel-bin/tar-oci-index/tarball.tar

## to push the image a repo, edit cmd/BUILD.bazel and set the push-image target repository
bazel run cmd:push-image  
```

side note:  getting bazel to work with google apis is a bit brittle.  

make the following edits to `repositories.bzl`

```bash
### add build_file_proto_mode directive here
    go_repository(
        name = "com_github_googleapis_gax_go_v2",
        build_file_proto_mode = "disable_global",        
        importpath = "github.com/googleapis/gax-go/v2",
        sum = "h1:9gWcmF85Wvq4ryPFvGFaOgPIs1AQX0d0bcbGw4Z96qg=",
        version = "v2.12.4",
    )    

### after upgrading google.golang.org/protobuf-->v1.33.0, i had to comment out 
    #go_repository(
    #    name = "org_golang_google_protobuf",
    #    importpath = "google.golang.org/protobuf",
    #    sum = "h1:9ddQBjfCyZPOHPUiPxpYESBLc+T8P3E+Vo4IbKZgFWg=",
    #    version = "v1.34.1",
    #)
```

#### Building with Kaniko

The container image is built using kaniko with the `--reproducible` flag enabled:

```bash
export TAG=...
docker run    -v `pwd`:/workspace -v $HOME/.docker/config.json:/kaniko/.docker/config.json:ro    -v /var/run/docker.sock:/var/run/docker.sock   \
      gcr.io/kaniko-project/executor@sha256:034f15e6fe235490e64a4173d02d0a41f61382450c314fffed9b8ca96dff66b2  \
      --dockerfile=Dockerfile \
      --reproducible \
      --destination "docker.io/salrashid123/gcemetadataserver:$TAG" \
      --context dir:///workspace/

syft packages docker.io/salrashid123/gcemetadataserver:$TAG
skopeo copy  --preserve-digests  docker://docker.io/salrashid123/gcemetadataserver:$TAG docker://docker.io/salrashid123/gcemetadataserver:latest
```


This is useful for unit tests and fakes.  For additional examples, please see the `server_test.go` and `cmd/main.go`

#### Verify Release Binary

If you download a binary from the "Releases" page, you can verify the signature with GPG:

```bash
gpg --keyserver keyserver.ubuntu.com --recv-keys 5D8EA7261718FE5728BA937C97341836616BF511

## to verify the checksum file for a given release:
wget https://github.com/salrashid123/gce_metadata_server/releases/download/v3.4.1/gce_metadata_server_3.4.1_checksums.txt
wget https://github.com/salrashid123/gce_metadata_server/releases/download/v3.4.1/gce_metadata_server_3.4.1_checksums.txt.sig

gpg --verify gce_metadata_server_3.4.1_checksums.txt.sig gce_metadata_server_3.4.1_checksums.txt
```

#### Verify Container Image Signature

The images are also signed using my github address (`salrashid123@gmail`).  If you really want to, you can verify each signature usign `cosign`:

```bash
## for tag/version  3.4.0:
IMAGE="index.docker.io/salrashid123/gcemetadataserver@sha256:c3cec9e18adb87a14889f19ab0c3c87d66339284b35ca72135ff9dcd58a59671"

## i signed it directly, keyless:
# $ cosign sign $IMAGE

## which you can verify:
$ cosign verify --certificate-identity=salrashid123@gmail.com  --certificate-oidc-issuer=https://github.com/login/oauth $IMAGE | jq '.'

## search and get 
# $ rekor-cli search --rekor_server https://rekor.sigstore.dev  --email salrashid123@gmail.com
# $ rekor-cli get --rekor_server https://rekor.sigstore.dev  --log-index $LogIndex  --format=json | jq '.'
```

## GCE mTLS

GCE metadata server also supports a mode where [mTLS is used](https://cloud.google.com/compute/docs/metadata/overview#https-mds)

You can enable this mode with the following flags but be aware, no client library supports it afaik. 

```bash
./gce_metadata_server -logtostderr --configFile=config.json \
  -alsologtostderr -v 5 \
  -port :8080 --usemTLS \
  --serverCert certs/server.crt \
  --serverKey certs/server.key --rootCAmTLS certs/root.crt  \
  --serviceAccountFile certs/metadata-sa.json 

curl -s -H 'Metadata-Flavor: Google' --connect-to metadata.google.internal:443:127.0.0.1:8080 \
   --cert certs/client.crt --key certs/client.key     --cacert certs/root.crt \
   https://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

For an example on how the [GCE guest agent](https://github.com/GoogleCloudPlatform/guest-agent/blob/main/google_guest_agent/agentcrypto/mtls_mds.go#L136) extracts the root ca from UEFI and decrypts the client cert/key from metadata server, see [certextract.go](https://gist.github.com/salrashid123/c1de41bf380c1f9a3602675276977e48)

For an example of how to invoke the mTLS endpoint and use it with a client library, see [examples/goapp_mtls/main.go](examples/goapp_mtls/main.go)

Note that GCE issues client certificates that are rotated periodically.  Infact, the client certificate is set to expire in a week:

For example, the client certificate from a real GCE instance with metadata TLS shows a validity for about a week.

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            82:f6:44:68:9e:b5:b2:cc:81:35:ff:29:61:1d:bf:9e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Google Compute Internal, CN=google.internal
        Validity
            Not Before: Aug 13 23:05:26 2024 GMT
            Not After : Aug 20 23:10:26 2024 GMT
        Subject: C=US, O=Google Compute Engine, CN=instance-1
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Alternative Name: 
                DNS:instance-1.c.srashid-test2.internal
            X509v3 Extended Key Usage: critical
                TLS Web Client Authentication
    Signature Algorithm: ecdsa-with-SHA256
```

## Envoy Authentication Filter

[GCP Authentication Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/gcp_authn_filter) provides a way to for envoy to automatically inject an `id_token` into the upstream request.

It does this as an http filter that first acquires the token from a metadata service.  If you want to use this repos' metadata service to test with, 


run enovy 

```bash
cd example/envoy_gcp_authentication/

docker cp `docker create  envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/

/tmp/envoy -c sidecar.yaml -l debug
```

then when you invoke envoy, the request has the id_token added on by envoy.  The echo response in this example shows the headers upstream:


```bash
$ curl -v  http://localhost:18080/get
{
  "args": {}, 
  "headers": {
    "Accept": "*/*", 
    "Authorization": "Bearer eyJhbGciOiJSU...", 
    "Host": "localhost", 
    "User-Agent": "curl/8.8.0", 
    "X-Amzn-Trace-Id": "Root=1-672a30f1-74e63bf55e1f189f3eedac33", 
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000"
  }, 
  "origin": "71.127.34.114", 
  "url": "https://localhost/get"
}
```

the token has the audience set to the envoy configuration file

```json
{
  "aud": "http://test.com",
  "azp": "metadata-sa@$PROJECT.iam.gserviceaccount.com",
  "email": "metadata-sa@$PROJECT.iam.gserviceaccount.com",
  "email_verified": true,
  "exp": 1730821889,
  "iat": 1730818289,
  "iss": "https://accounts.google.com",
  "sub": "100890260483227123111"
}
```

## Metrics

Basic latency and counter Prometheus metrics are enabled using the `--metrisEnabled` flag.

Once enabled, path latency is recoreded at the default prometheus endpoint at `http://localhost:9000/metrics`.

Apart from latency, any dynamic field for access or identity tokens also has a counter and status metric surfaced.

## Testing

a lot todo here, right...thats just life

```bash
$ go test -v 

=== RUN   TestBasePathRedirectHandler
--- PASS: TestBasePathRedirectHandler (0.00s)
=== RUN   TestProjectIDHandler
--- PASS: TestProjectIDHandler (0.00s)
=== RUN   TestAccessTokenHandler
--- PASS: TestAccessTokenHandler (0.00s)
=== RUN   TestAccessTokenDefaultCredentialHandler
--- PASS: TestAccessTokenDefaultCredentialHandler (0.00s)
=== RUN   TestAccessTokenComputeCredentialHandler
--- PASS: TestAccessTokenComputeCredentialHandler (0.00s)
=== RUN   TestAccessTokenEnvironmentCredentialHandler
--- PASS: TestAccessTokenEnvironmentCredentialHandler (0.00s)
=== RUN   TestOnGCEHandler
--- PASS: TestOnGCEHandler (0.00s)
=== RUN   TestProjectNumberHandler
--- PASS: TestProjectNumberHandler (0.00s)
=== RUN   TestInstanceIDHandler
--- PASS: TestInstanceIDHandler (0.00s)
PASS
ok  	github.com/salrashid123/gce_metadata_server	0.053s
```
