
# GCE Metadata Server Emulator


## Background
 This script acts as a GCE's internal metadata server for local testing/emulation.

 This script also returns an access token that can be used directly by [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials).  Although applciation default credentials will return access_tokens in context with your environment, running a sample code locally is not precisely the same thing as running on GCP as the context paths differ.  For example, Application Defaults on GCE may use a gcloud credentials or JSON key file while running locally but the same code will use GCE's metadata server remotely.  You can, ofcourse, directly call [com.google.api.client.googleapis.compute.ComputeCredential](https://developers.google.com/api-client-library/java/google-api-java-client/reference/1.20.0/com/google/api/client/googleapis/compute/ComputeCredential) while on GCP but that isn't portable and will only work on GCE (without an emulator).

 Another usecase for this is to verify how Application Defaults will behave while running a local docker container locally: A local running docker container will not have access to GCE's metadata server but by running an emulator locally and forcing the container to connect, you are basically providing the container access to a similar metadata auth_token provider. 

* [GCE Metadata Server](https://cloud.google.com/compute/docs/storing-retrieving-metadata)


 The script performs the following:
 
   *  returns the access_token for your the gcloud CLI.
   *  returns project information for your environment.
   *  return custom key-value attributes (either user-defined local or from the actual GCP project).

## Usage

This script runs a basic webserver and responds back as the Google Compute Engine's metadata server.  A local webserver
runs on a non-privleged port (default: 18080) and optionally uses a gcloud cli wrapper to recall the current contexts/configurations for the access_token 
and optional live project user-defined metadata.  You do not have to use the gcloud CLI wrapper code and simply elect to return a static access_token or metadata.


1. You need to install a utility to map port :80 traffic since REST calls to the metadata server are HTTP.  The following use 'socat':
```
sudo apt-get install socat
```

2. Alter /etc/hosts
```
# /etc/hosts
127.0.0.1       metadata metadata.google.internal
```

3. Run socat
```
sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:18080
```
or iptables
```
sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 18080
```

4. Add supporting libraries for the proxy:
```
cd gce_metadata_server/
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

5. Run the script
directly:
```
python gce_metadata_server.py
```
or via gcunicorn
```
gunicorn -b :18080 gce_metadata_server:app
```

6. Test access to the metadata server
In a new window, run
```
 curl -v -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
 **NOTE** 
 > the access_token returned by this script to your app is for you gcloud client and is *LIVE*.
 > If you use this token in a script to simulate delete of your GCS bucket, you'll actually delete it!! 
 > You are free to acquire an access_token by any other means and return that instead.
 > (eg. use a service account json file as shown here:
 >    github.com/salrashid: [service.py](https://github.com/salrashid123/gcpsamples/blob/master/auth/service/pyapp/service.py)  


![Meta Proxy](images/metadata_proxy.png)


### Misc

### Access from containers
If you run an app inside a docker container on your laptop that needs to access this, please be sure to enable 
host (--net=host) access/networking:
```
docker run -p host_port:container_port --net=host -t <your_image> 
```
This will allow the container to 'see' the local interface on the laptop.

#### gcloud CLI wrapper
This script utilizes [gcloud_wrapper.py](gcloud_wrapper.py) which is basically a python wrapper around the actual gcloud CLI (google cloud sdk).
What this script allows you to do is acquire gcloud's cli capabilities directly in python code automatically.

#### Port mapping :80 --> :18080
Since GCE's metadata server listens on http for :80, this script relies on utilities like 'socat' to redirect port traffic.
You are free to either run the script on port :80 directly (as root), or use a utilitity like iptables, HAProxy, nginx, etc to do this mapping.

iptables:
```
sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 8080
```

#### Extending the sample
You can extend this sample for any arbitrary metadta you are interested in emulating (eg, disks, hostname, etc).
Simply make an @app.route()  for the path and either use the gcloud wrapper or hardcode the response you're interested in

#### Aliasing Metadata Servers IP
GCE's metadata server's IP address on GCE is 169.254.169.254.  If you want to mimic accessing the metadata server directly, you need to 
alias an interface for this address:

```bash
sudo ifconfig lo:0 169.254.169.254 up

/sbin/ifconfig -a
lo:0      Link encap:Local Loopback  
          inet addr:169.254.169.254  Mask:255.255.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
```
After which you can get a token even if you run:
```
curl -v -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

**NOTE**  It is strongly advised to access the metadata server using the hostname, not IP

#### Alternatives to Metadata tokens for containers

You can certainly provide environment variables on container startup and then map volumes to allow for applicaiton defaults.  (for example:)

 ```
docker run -p 8080:8080 -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/<YOUR_CERT_JSON_FILE>.json  -v  /tmp/:/tmp -t your_image
 ```
