### TODO

#### Endpoint implementations

Some MDS endpoints for potential future implementation if needed:

```bash
$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/'

credentials/
gce-workload-certificates/
guest-attributes/
partner-attributes/
workload-certificates-config-status
workload-identities
workload-trusted-root-certs
```


##### Implement Partner Attributes

- [https://cloud.google.com/compute/docs/metadata/overview#partner_attributes](https://cloud.google.com/compute/docs/metadata/overview#partner_attributes)


```text
$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/'
iam.googleapis.com/
wc.compute.googleapis.com/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/iam.googleapis.com'
/computeMetadata/v1/instance/partner-attributes/iam.googleapis.com/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/iam.googleapis.com/'
workload-identity

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/iam.googleapis.com/workload-identity'
spiffe://workload-pool-test.global.708288290784.workload.id.goog/ns/default-ns/sa/managed-identity-1


$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com'
/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/'
certificate-issuance-config/
trust-config/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config'
/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/'
key_algorithm
primary_certificate_authority_config/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/key_algorithm'
ecdsa-p256

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/primary_certificate_authority_config/'
certificate_authority_config/

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/primary_certificate_authority_config/certificate_authority_config/'
ca_pool

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/partner-attributes/wc.compute.googleapis.com/certificate-issuance-config/primary_certificate_authority_config/certificate_authority_config/ca_pool'
projects/srashid-test2/locations/us-central1/caPools/s-pool-1
```


##### Implement Workload Identities

```text
$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/workload-certificates-config-status'
{
 "partnerMetadataConfigsErrors": {}
}

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/workload-identities'
{
 "workloadCredentials": {
  "spiffe://workload-pool-test.global.708288290784.workload.id.goog/ns/default-ns/sa/managed-identity-1": {
   "certificatePem": "-----BEGIN CERTIFICATE-----\nMIICyzCCAnGgAwIBAgIUALOsFkzZ8F63H1xrJ225TAUqVLUwCgYIKoZIzj0EAwIw\nQjEkMCIGA1UECgwbU1VCT1JESU5BVEVfQ0FfT1JHQU5JWkFUSU9OMRowGAYDVQQD\nDBFTVUJPUkRJTkFURV9DQV9DTjAeFw0yNTA1MjYwOTU0MTZaFw0yNTA1MjcwOTU0\nMTVaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQNvxtHwugQ/s1gtDAuwRaQ\nkzkIxkXdClFYBvxrv/iAb6DHBGZr0r/gPaZtQbVskt6LxcME6SF9iIhe7KCvHqr9\no4IBhTCCAYEwDgYDVR0PAQH/BAQDAgOIMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\nBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRUIVX1PtzkDKLNwO7v0ZMb\nx4xKoDAfBgNVHSMEGDAWgBQSikos69Iyzz2WeXUekdivPWy4XjCBjQYIKwYBBQUH\nAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY3\nNDM3ZjY0LTAwMDAtMmU3NS05ZGQwLTMwZmQzODE0NTM3Yy5zdG9yYWdlLmdvb2ds\nZWFwaXMuY29tLzVjNTQ2MGIxN2ExZWY2Mjc3YTg2L2NhLmNydDByBgNVHREBAf8E\naDBmhmRzcGlmZmU6Ly93b3JrbG9hZC1wb29sLXRlc3QuZ2xvYmFsLjcwODI4ODI5\nMDc4NC53b3JrbG9hZC5pZC5nb29nL25zL2RlZmF1bHQtbnMvc2EvbWFuYWdlZC1p\nZGVudGl0eS0xMAoGCCqGSM49BAMCA0gAMEUCIQDAXsHp+mNoNKbunxcyKeoGvUiK\nkj3lmBnHnrIoR8Ot+QIgDayPiZVsew1xFa+NsMV7u/guvJILwz03wKbAEKECHZE=\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgITT3ZqBowhmk0rEeIS/acfjpV/njAKBggqhkjOPQQDAjA0\nMR0wGwYDVQQKDBRST09UX0NBX09SR0FOSVpBVElPTjETMBEGA1UEAwwKUk9PVF9D\nQV9DTjAeFw0yNDEyMDExMjU5MjZaFw0yNzEyMDIwNjI1NDNaMEIxJDAiBgNVBAoM\nG1NVQk9SRElOQVRFX0NBX09SR0FOSVpBVElPTjEaMBgGA1UEAwwRU1VCT1JESU5B\nVEVfQ0FfQ04wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARpylmIgqp0lyP07/fq\nkitfPZfZd9VUXxJ80l5Xn+Fq38bTLd70kGNVneltH1opo+FrYtaPQwDp8MmA8l/Y\nSaH0o4IBnDCCAZgwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQSikos69Iy\nzz2WeXUekdivPWy4XjAfBgNVHSMEGDAWgBTbP5nu7Amu6liM6pfvt+kiC3L4yzCB\njQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1j\nb250ZW50LTY3NGJkMzNjLTAwMDAtMmI3Ny1hNmViLTg4M2QyNGY1YzJhYy5zdG9y\nYWdlLmdvb2dsZWFwaXMuY29tL2FlNGI5ZTI4MDIyN2UyMmQ4MWNhL2NhLmNydDCB\nggYDVR0fBHsweTB3oHWgc4ZxaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY3NGJk\nMzNjLTAwMDAtMmI3Ny1hNmViLTg4M2QyNGY1YzJhYy5zdG9yYWdlLmdvb2dsZWFw\naXMuY29tL2FlNGI5ZTI4MDIyN2UyMmQ4MWNhL2NybC5jcmwwCgYIKoZIzj0EAwID\nSAAwRQIgcBLIHIjjJUqo6h2WT65dbsfDxBffqS4TKKJpOeaubfUCIQDmiKpTXPUI\ncGARgB7v0V8LAZV9jQ2KzcBvPlqMV91U3g==\n-----END CERTIFICATE-----\n",
   "privateKeyPem": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHPm+JtH06TC8MGuRJZwDXS75JCMLWJfIsPUwtCPcC8qoAoGCCqGSM49\nAwEHoUQDQgAEDb8bR8LoEP7NYLQwLsEWkJM5CMZF3QpRWAb8a7/4gG+gxwRma9K/\n4D2mbUG1bJLei8XDBOkhfYiIXuygrx6q/Q==\n-----END EC PRIVATE KEY-----\n"
  }
 }
}

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/workload-trusted-root-certs'
{
 "trustAnchors": {
  "workload-pool-test.global.708288290784.workload.id.goog": {
   "trustAnchorsPem": "-----BEGIN CERTIFICATE-----\nMIIB0TCCAXagAwIBAgIUANa7r1/8U0tLDhkS9lsjqR5Au3swCgYIKoZIzj0EAwIw\nNDEdMBsGA1UECgwUUk9PVF9DQV9PUkdBTklaQVRJT04xEzARBgNVBAMMClJPT1Rf\nQ0FfQ04wHhcNMjQxMjAxMTI1NzUzWhcNMzQxMjAxMjMwNTMzWjA0MR0wGwYDVQQK\nDBRST09UX0NBX09SR0FOSVpBVElPTjETMBEGA1UEAwwKUk9PVF9DQV9DTjBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABEl0aH0R90R6Ku/75G5tntdMNrDXKYr6dqOf\nswHC0bruOa20tihKA97BuNrnT4CO03PBUiWQDf2BVTGtusXm+MyjZjBkMA4GA1Ud\nDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTbP5nu7Amu\n6liM6pfvt+kiC3L4yzAfBgNVHSMEGDAWgBTbP5nu7Amu6liM6pfvt+kiC3L4yzAK\nBggqhkjOPQQDAgNJADBGAiEA7K2jdvPXJ7tv2EOLpNjZLBrVnP/FA+/4SI6SgR2O\nGhMCIQCX8Uid4m5fdZ+vZVVvaxrbO5X/pn37N98R8t1apbJv4g==\n-----END CERTIFICATE-----\n"
  }
 }
}
```

##### Implement GCE Workload Certificates

```text
$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/gce-workload-certificates/'
config-status
trust-anchors
workload-identities

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/gce-workload-certificates/config-status'
{
 "partnerMetadataConfigsErrors": {}
}

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/gce-workload-certificates/trust-anchors'
{
 "trustAnchors": {
  "workload-pool-test.global.708288290784.workload.id.goog": {
   "trustAnchorsPem": "-----BEGIN CERTIFICATE-----\nMIIB0TCCAXagAwIBAgIUANa7r1/8U0tLDhkS9lsjqR5Au3swCgYIKoZIzj0EAwIw\nNDEdMBsGA1UECgwUUk9PVF9DQV9PUkdBTklaQVRJT04xEzARBgNVBAMMClJPT1Rf\nQ0FfQ04wHhcNMjQxMjAxMTI1NzUzWhcNMzQxMjAxMjMwNTMzWjA0MR0wGwYDVQQK\nDBRST09UX0NBX09SR0FOSVpBVElPTjETMBEGA1UEAwwKUk9PVF9DQV9DTjBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABEl0aH0R90R6Ku/75G5tntdMNrDXKYr6dqOf\nswHC0bruOa20tihKA97BuNrnT4CO03PBUiWQDf2BVTGtusXm+MyjZjBkMA4GA1Ud\nDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTbP5nu7Amu\n6liM6pfvt+kiC3L4yzAfBgNVHSMEGDAWgBTbP5nu7Amu6liM6pfvt+kiC3L4yzAK\nBggqhkjOPQQDAgNJADBGAiEA7K2jdvPXJ7tv2EOLpNjZLBrVnP/FA+/4SI6SgR2O\nGhMCIQCX8Uid4m5fdZ+vZVVvaxrbO5X/pn37N98R8t1apbJv4g==\n-----END CERTIFICATE-----\n"
  }
 }
}

$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/gce-workload-certificates/workload-identities'
{
 "workloadCredentials": {
  "spiffe://workload-pool-test.global.708288290784.workload.id.goog/ns/default-ns/sa/managed-identity-1": {
   "certificatePem": "-----BEGIN CERTIFICATE-----\nMIICyzCCAnGgAwIBAgIUALOsFkzZ8F63H1xrJ225TAUqVLUwCgYIKoZIzj0EAwIw\nQjEkMCIGA1UECgwbU1VCT1JESU5BVEVfQ0FfT1JHQU5JWkFUSU9OMRowGAYDVQQD\nDBFTVUJPUkRJTkFURV9DQV9DTjAeFw0yNTA1MjYwOTU0MTZaFw0yNTA1MjcwOTU0\nMTVaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQNvxtHwugQ/s1gtDAuwRaQ\nkzkIxkXdClFYBvxrv/iAb6DHBGZr0r/gPaZtQbVskt6LxcME6SF9iIhe7KCvHqr9\no4IBhTCCAYEwDgYDVR0PAQH/BAQDAgOIMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\nBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRUIVX1PtzkDKLNwO7v0ZMb\nx4xKoDAfBgNVHSMEGDAWgBQSikos69Iyzz2WeXUekdivPWy4XjCBjQYIKwYBBQUH\nAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY3\nNDM3ZjY0LTAwMDAtMmU3NS05ZGQwLTMwZmQzODE0NTM3Yy5zdG9yYWdlLmdvb2ds\nZWFwaXMuY29tLzVjNTQ2MGIxN2ExZWY2Mjc3YTg2L2NhLmNydDByBgNVHREBAf8E\naDBmhmRzcGlmZmU6Ly93b3JrbG9hZC1wb29sLXRlc3QuZ2xvYmFsLjcwODI4ODI5\nMDc4NC53b3JrbG9hZC5pZC5nb29nL25zL2RlZmF1bHQtbnMvc2EvbWFuYWdlZC1p\nZGVudGl0eS0xMAoGCCqGSM49BAMCA0gAMEUCIQDAXsHp+mNoNKbunxcyKeoGvUiK\nkj3lmBnHnrIoR8Ot+QIgDayPiZVsew1xFa+NsMV7u/guvJILwz03wKbAEKECHZE=\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgITT3ZqBowhmk0rEeIS/acfjpV/njAKBggqhkjOPQQDAjA0\nMR0wGwYDVQQKDBRST09UX0NBX09SR0FOSVpBVElPTjETMBEGA1UEAwwKUk9PVF9D\nQV9DTjAeFw0yNDEyMDExMjU5MjZaFw0yNzEyMDIwNjI1NDNaMEIxJDAiBgNVBAoM\nG1NVQk9SRElOQVRFX0NBX09SR0FOSVpBVElPTjEaMBgGA1UEAwwRU1VCT1JESU5B\nVEVfQ0FfQ04wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARpylmIgqp0lyP07/fq\nkitfPZfZd9VUXxJ80l5Xn+Fq38bTLd70kGNVneltH1opo+FrYtaPQwDp8MmA8l/Y\nSaH0o4IBnDCCAZgwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQSikos69Iy\nzz2WeXUekdivPWy4XjAfBgNVHSMEGDAWgBTbP5nu7Amu6liM6pfvt+kiC3L4yzCB\njQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1j\nb250ZW50LTY3NGJkMzNjLTAwMDAtMmI3Ny1hNmViLTg4M2QyNGY1YzJhYy5zdG9y\nYWdlLmdvb2dsZWFwaXMuY29tL2FlNGI5ZTI4MDIyN2UyMmQ4MWNhL2NhLmNydDCB\nggYDVR0fBHsweTB3oHWgc4ZxaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY3NGJk\nMzNjLTAwMDAtMmI3Ny1hNmViLTg4M2QyNGY1YzJhYy5zdG9yYWdlLmdvb2dsZWFw\naXMuY29tL2FlNGI5ZTI4MDIyN2UyMmQ4MWNhL2NybC5jcmwwCgYIKoZIzj0EAwID\nSAAwRQIgcBLIHIjjJUqo6h2WT65dbsfDxBffqS4TKKJpOeaubfUCIQDmiKpTXPUI\ncGARgB7v0V8LAZV9jQ2KzcBvPlqMV91U3g==\n-----END CERTIFICATE-----\n",
   "privateKeyPem": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHPm+JtH06TC8MGuRJZwDXS75JCMLWJfIsPUwtCPcC8qoAoGCCqGSM49\nAwEHoUQDQgAEDb8bR8LoEP7NYLQwLsEWkJM5CMZF3QpRWAb8a7/4gG+gxwRma9K/\n4D2mbUG1bJLei8XDBOkhfYiIXuygrx6q/Q==\n-----END EC PRIVATE KEY-----\n"
  }
 }
}
```

##### Implement Guest Attributes

```bash
$ curl -s -H "Metadata-Flavor: Google" 'http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/'
Guest attributes endpoint access is disabled.
```