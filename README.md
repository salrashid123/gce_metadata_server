
# GCE Metadata Server Emulator


## Background
This script acts as a GCE's internal metadata server for local testing/emulation.

It returns a live access_token that can be used directly by [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) transparently.

 This is useful to test any script or code locally that my need to contact GCE's metadata server for custom, user-defined variables or access_tokens.

 Another usecase for this is to verify how Application Defaults will behave while running a local docker container: A local running docker container will not have access to GCE's metadata server but by bridging your container to the emulator, you are basically allowing GCP API access directly from within a container on your local workstation (vs. running the code comprising the container directly on the workstation and relying on gcloud credentials (not metadata)).

For more inforamtion on the request-response characteristics: 
* [GCE Metadata Server](https://cloud.google.com/compute/docs/storing-retrieving-metadata)

 The script performs the following:
	* returns the access_token provided by your desktop gcloud CLI.
	  * (you are free to substitute any other mechanism to source tokens).
	* returns project information for your environment.
	  * (again, based on gcloud credentials)
	* return custom key-value attributes 
	  * (either user-defined local or from the actual GCP project).
    * returns a live GCE VM's instance metadata such as its disk and networks configuration
      * (to use this mode, you need to extend the script as described below and use the gcloud wrapper) 

## Usage

This script runs a basic webserver and responds back as the Google Compute Engine's metadata server.  A local webserver
runs on a non-privleged port (default: 18080) and optionally uses a gcloud cli wrapper to recall the current contexts/configurations for the access_token 
and optional live project user-defined metadata.  You do not have to use the gcloud CLI wrapper code and simply elect to return a static access_token or metadata.


You need to install a utility to map port :80 traffic since REST calls to the metadata server are HTTP.  The following use 'socat':
```
sudo apt-get install socat
```

* Reconfigure the /etc/hosts to resolve the metadata server
```
# /etc/hosts
127.0.0.1       metadata metadata.google.internal
```

* Create metadata server IP alias

GCE's metadata server's IP address on GCE is 169.254.169.254.  Certain application default credential libraries for
the metadata server by IP address.   The following steps creates an IP address alias for the local system.

```bash
sudo ifconfig lo:0 169.254.169.254 up
```
You can veirify the alias was created by checking _ifconfig_
```
/sbin/ifconfig -a
lo:0      Link encap:Local Loopback  
          inet addr:169.254.169.254  Mask:255.255.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
```
Once the interface is seetup, you can access it via the IP:
```
curl -v -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```
(on windows)
```
netsh interface ipv4 add address "Loopback Pseudo-Interface 1" 169.254.169.254 255.255.0.0
```

* Run socat or iptables
```
sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:18080
```
or
```
sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 18080
```
_note:_  socat is pretty much for unit testing.  For anything else, try iptables and gunicorn.

* Add supporting libraries for the proxy:
```
cd gce_metadata_server/
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

* Run the metadata server
directly:
```
python gce_metadata_server.py
```
or **preferably** via [gunicorn](http://docs.gunicorn.org/en/stable/install.html)
```
gunicorn -b :18080 gce_metadata_server:app
```

* Test access to the metadata server
In a new window, run
```
 curl -v -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
 **NOTE** 
 > the access_token returned by this script to your app is for you gcloud client and is *LIVE*.
 > If you use this token in a script to simulate delete of your GCS bucket, you'll actually delete it!! 
 > You are free to acquire an access_token by any other means and return that instead.
 > (eg. use a service account json file as shown here:
 >    github.com/salrashid123: [service.py](https://github.com/salrashid123/gcpsamples/blob/master/auth/service/pyapp/service.py)  


![Meta Proxy](images/metadata_proxy.png)

### Misc

### Access from containers
If you run an app inside a docker container on your laptop that needs to access the metadata server:

#### Add host networking to the running Container (--net=host)

host (**--net=host**) access/networking:
```
docker run --net=host -t _your_image_ 
```
This will allow the container to 'see' the local interface on the laptop.  The disadvantage is the host's interface is the containers as well

> *NOTE:*   using --net=host is only recommended for testing; For more information see:

* [Docker Networking](https://docs.docker.com/v1.8/articles/networking/#container-networking)
* [Embedded DNS server in user-defined networks](https://docs.docker.com/engine/userguide/networking/configure-dns/#/embedded-dns-server-in-user-defined-networks)

##### Testing Application Default Credentials through from a container

The following sample details testing application default credentials from inside a docker container.  To use, you need
to set the interface alias and edit /etc/hosts file as describe above.


###### Dockerfile
```
FROM debian:latest

RUN apt-get -y update
RUN apt-get install -y curl python python-pip
RUN pip install oauth2client google-api-python-client httplib2

ADD . /app
WORKDIR /app

ENTRYPOINT ["python", "compute.py"]
```

###### compute.py
```python
#!/usr/bin/python

import httplib2
from apiclient.discovery import build
from oauth2client.client import GoogleCredentials
#from oauth2client.contrib.gce import AppAssertionCredentials

scope='https://www.googleapis.com/auth/userinfo.email'

#credentials = AppAssertionCredentials(scope=scope)
credentials = GoogleCredentials.get_application_default()
if credentials.create_scoped_required():
  credentials = credentials.create_scoped(scope)

http = httplib2.Http()
credentials.authorize(http)

service = build(serviceName='oauth2', version= 'v2',http=http)
resp = service.userinfo().get().execute()
print resp['email']
```

###### build
```
docker build -t compute .
```

###### run
```
docker run -t --net=host compute
```

#### gcloud CLI wrapper
This script utilizes [gcloud_wrapper.py](gcloud_wrapper.py) which is basically a python wrapper around the actual gcloud CLI (google cloud sdk).
What this script allows you to do is acquire gcloud's cli capabilities directly in python code automatically.


#### Acquire remote access_token from GCE Instance
If you require the live access_token issued by the actual metadata server on the GCE instance, you can invoke 
```python
def __getAccessTokenFromInstance(instance):
    logging.info('Getting access_token from instance ' + instance)
    
    # if gcloud is installed remotely    
    #token = GCloud(['--configuration', gcloud_configuraiton, 'compute','ssh', instance, 'gcloud auth print-access-token', '--format', 'json()'])
    #logging.info('access_token: ' + str(token))

    # if curl is installed remotely
    #result = GCloud(['--configuration', gcloud_configuraiton, 'compute','ssh',instance, \
    #  'curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"'])
    #p = json.loads(result)
    #token = p['access_token']
```

What that section attempts to do is invoke gcloud ssh and execute a remote command.  In this case, either try to capture the remote system's gcloud access token or run 
curl against the real metadata server.

> **NOTE** This function does not work as the remote ssh commands is not returned in gcloud but echo'd to the output.  Capturing the redirect is possible but I have not
> spent the time to account for the redirection GCloud() itself does already.

#### Port mapping :80 --> :18080
Since GCE's metadata server listens on http for :80, this script relies on utilities like 'socat' to redirect port traffic.  _socat_ has pretty
basic connection handling so you'd be better with iptables, gunicorn.
You are free to either run the script on port :80 directly (as root), or use a utilitity like iptables, HAProxy, nginx, etc to do this mapping.

iptables:
```
sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 18080
```

#### Extending the sample
You can extend this sample for any arbitrary metadta you are interested in emulating (eg, disks, hostname, etc).
Simply make an @app.route()  for the path and either use the gcloud wrapper or hardcode the response you're interested in

#### Alternatives to Metadata tokens for containers

You can certainly provide environment variables on container startup and then map volumes to allow for applicaiton defaults.  (for example:)

```
docker run -p 8080:8080 -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/<YOUR_CERT_JSON_FILE>.json  -v  /tmp/:/tmp -t your_image
```