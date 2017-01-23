
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


* **1. Reconfigure the /etc/hosts to resolve the metadata server**
```
# /etc/hosts
127.0.0.1       metadata metadata.google.internal
```
> Note: [dockerimages/metadatadns/](dockerimages/metadatadns/) contains a DNS server with the __google.internal__ as a zone.  You can use that as well (described at the end of this document).

* **2. Create metadata IP alias**

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
(on windows)
```
netsh interface ipv4 add address "Loopback Pseudo-Interface 1" 169.254.169.254 255.255.0.0
```

* **3. Run socat**

You need to install a utility to map port :80 traffic since REST calls to the metadata server are HTTP.  The following usees 'socat':
```
sudo apt-get install socat

sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:18080
```


Alternatively, you can create an OUTPUT iptables rule to intercept and redirect the metadata traffic.

```
iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j REDIRECT --to-port 18080
```

* **5. Add supporting libraries**
```
cd gce_metadata_server/
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

The snippet above uses virtualenv though you can just use pip install directly

* **6. Run the metadata server**
directly:
```
python gce_metadata_server.py
```
or **preferably** via [gunicorn](http://docs.gunicorn.org/en/stable/install.html)
```
gunicorn -b :18080 gce_metadata_server:app
```

* **7. Test access to the metadata server**
In a new window, run
```
curl -v -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

curl -v -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

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
If you run an app inside a docker container that needs to access the metadata server, there are two options:
* use bridge networking (preferred)
* use host networking

#### Add bridge networking to the running Container (--net=bridge)
To use bridge networking, you need to first
* create the interface alias for 169.254.169.254 --> lo:0
* make sure ip_forward is enabled  _sudo sysctl -w net.ipv4.ip\_forward=1_
* run socat to forward 80-->18080
* start the container and pass in the host files pointing to the local emulator's ip address:

```
docker run -t --net=bridge --add-host metadata.google.internal:169.254.169.254 --add-host metadata:169.254.169.254 _your-image_
```
You may need to drop existing firewall rules and then restart the docker daemon to prevent conflicts or overrides.

#### Add host networking to the running Container (--net=host)

host (**--net=host**) access/networking:
```
docker run --net=host -t _your-image_ 
```
This will allow the container to 'see' the local interface on the laptop.  The disadvantage is the host's interface is the containers as well

> *NOTE:*   using --net=host is only recommended for testing; For more information see:

* [Docker Networking](https://docs.docker.com/v1.8/articles/networking/#container-networking)
* [Embedded DNS server in user-defined networks](https://docs.docker.com/engine/userguide/networking/configure-dns/#/embedded-dns-server-in-user-defined-networks)

##### Testing Application Default Credentials through from a container

The following sample details testing application default credentials from inside a docker container.  To use, you need
to set the interface alias and edit /etc/hosts file as describe above.

_Note:_  Python's application default credentials looks for the [metadata server by IP address](https://github.com/google/oauth2client/blob/master/oauth2client/client.py#L111)
 which is why the interface alias is needed.


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

With default bridge networking 
```bash
docker run -t --net=bridge --add-host metadata.google.internal:169.254.169.254 --add-host metadata:169.254.169.254 compute
```

or with host networking
```bash
docker run -t --net=host compute
```

#### gcloud CLI wrapper
This script utilizes [gcloud_wrapper.py](gcloud_wrapper.py) which is basically a python wrapper around the actual gcloud CLI (google cloud sdk).
What this script allows you to do is acquire gcloud's cli capabilities directly in python code automatically.

#### Running metadata server emulator in containers

Its possible to run the metadata server emulator itself in a container.  To do this, you need to pass in credentials in the form of a cert file for 
the project you would like to emulate and use the following image that already has cloud SDK:

> [https://hub.docker.com/r/google/cloud-sdk/](https://hub.docker.com/r/google/cloud-sdk/)

* Download a .p12 certificate from the cloud console.  see: [Creating Service accounts](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount)

* Copy the certificate to _$HOME/emulators_  and note the certificate service account name.

  In the example, below, the service account name and cert file is:   _svc-2-429@mineral-minutia-820.iam.gserviceaccount.com_ and _GCPNETAppID-e4536f3eed76.p12_

* Generate a Volume:

```
docker run -t -v $HOME/emulators/:/data -i --name gcloud-config google/cloud-sdk gcloud auth activate-service-account svc-2-429@mineral-minutia-820.iam.gserviceaccount.com --key-file /data/GCPNETAppID-e4536f3eed76.p12 --project mineral-minutia-820

Activated service account credentials for: [svc-2-429@mineral-minutia-820.iam.gserviceaccount.com]
```

* Verify volume is initialized:
```bash
docker run --rm -ti --volumes-from gcloud-config google/cloud-sdk gcloud config list
```

You should see:
```
[component_manager]
disable_update_check = true
[core]
account = svc-2-429@mineral-minutia-820.iam.gserviceaccount.com
disable_usage_reporting = False
project = mineral-minutia-820
```

* Create the metadata server by extending the image:
[Dockerfile](dockerimages/metadataserver/Dockerfile)
```
FROM debian:latest

RUN apt-get -y update
RUN apt-get install -y curl python python-pip git
RUN curl https://sdk.cloud.google.com | bash

RUN pip install Flask
RUN git clone https://github.com/salrashid123/gce_metadata_server.git

WORKDIR /gce_metadata_server
ENV PATH /root/google-cloud-sdk/bin/:$PATH
ENTRYPOINT ["python", "gce_metadata_server.py"]
```
* build

```
docker build -t gcemetadataserver .
```
(this image is also available on Dockerhub as [salrashid123/gcemetadataserver](https://hub.docker.com/r/salrashid123/gcemetadataserver/)

* Run metadata server image
```
docker run -p 18080:18080 --rm -t --volumes-from gcloud-config gcemetadataserver
```

At this point, any metadata server request should go to the container and retrun an access token for the credential and project inside the container:
eg:

```
curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

{
  "access_token": "ya29.CjBbA6WsVY0-vT-ryIJ6vWYAcyUFN1a0afMvcAsywwZKwc5U9XX2SA5redacted", 
  "expires_in": 3600, 
  "token_type": "Bearer"
}
```

and then verify who owns the token:
```
curl https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=ya29.CjBbA6WsVY0-vT-ryIJ6vWYAcyUFN1a0afMvcAsywwZKwc5U9XX2SA5redacted
{
 "azp": "100147106996764479085",
 "aud": "100147106996764479085",
 "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/appengine.admin https://www.googleapis.com/auth/compute",
 "exp": "1473628884",
 "expires_in": "3469",
 "email": "svc-2-429@mineral-minutia-820.iam.gserviceaccount.com",
 "email_verified": "true",
 "access_type": "offline"
}
```

> *NOTE:* the token is owned by _svc-2-429@mineral-minutia-820.iam.gserviceaccount.com_

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

The following example of an iptables route 80 -> 18080 on the local interface
```
sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 18080
```

#### Allowing all firewall policies

The following set of command resets all firewall policies to allow all.

```bash
#!/bin/sh
echo "Stopping firewall and allowing everyone..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```

#### Extending the sample
You can extend this sample for any arbitrary metadta you are interested in emulating (eg, disks, hostname, etc).
Simply make an @app.route()  for the path and either use the gcloud wrapper or hardcode the response you're interested in

#### Alternatives to Metadata tokens for containers

You can certainly provide environment variables on container startup and then map volumes to allow for applicaiton defaults.  (for example:)

```
docker run -p 8080:8080 -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/<YOUR_CERT_JSON_FILE>.json  -v  /tmp/:/tmp -t your_image
```

#### Using the metadataDNS server container
Instead of editing the /etc/hosts, you can alter the containers' or laptop's /etc/resolv.conf to point to you own DNS server that understands
metadata.google.internal.

```
sudo docker run -t -p 53:53  -p 53:53/udp  salrashid123/metadatadns
```
The default image has the Google DNS as a forwarder:
[dockerimages/metadatadns/named.conf.options](dockerimages/metadatadns/named.conf.options):
```
forwarders {
    8.8.8.8;
};
```
If you need your forward to your own DNS servers, can rebuild the docker image and adjust the named.conf.options file accordingly.

You can verify the DNS server is running by accessing it at:
```
nslookup -port=53 metadata.google.internal  ip-address-of-your-laptop
```

#### Accessing the emulator from minikube
The following describes one way to run some code inside a [Minikube](https://github.com/kubernetes/minikube) cluster but still have access to the metadata server on your laptop.  When you run minikube, the Kubernetes pods
exist within a VirtualBox environment so accessing the metadata server by IP and hostname (metadata.google.internal) requires a couple of steps.

The approach descibed below is to basically reroute the IP for the metadata server to the emulator via iptables on the host.
To account for the DNS server, we run a local Bind9 server in a container.  The DNS server has a zones file for .google.internal and then we edit the /etc/resolv.conf file on the minikube node.
Since each pod picks up the DNS servers from the pod, each container knows about your DNS server.

The steps to follow:

*  Find the ip address for your laptop (wlan0 or eth0):
```
    /sbin/ifconfig -a
```

* Start the MetadataServer DNS Server 

Described in the seciton above.  Recommend starting the container via docker
```
sudo docker run -t -p 53:53  -p 53:53/udp  salrashid123/metadatadns
```

* Start minikube
```
     minikube start
```

* SSH in
```
     minikube ssh
```

* DELETE /etc/resolv.conf 

* vi /etc/resolv.conf
   and add the following
```
nameserver ip_address_on_your_laptop_from_step_1
nameserver 8.8.8.8
```
> Note, on way to override the the /etc/resolv.conf file on the node is to use the kubelet --resolv-conf= directive:
```
     minikube start --extra-config kubelet.ResolverConfig=$PATH_TO_CONFIG_IN_VM
```

* Exit the VM 

* Start the cluster again to pickup the changes
```
     minikube start
```
At this point the minikube cluster should be able to contact the metadata emulator and even resolve metadata.google.internal.

* Now create create the rc and service 

```
     kubectl create -f my-rs.yaml -f my-srv.yaml
```

I've written some sample containers which uses Application Default credentials here:
     [salrashid123/myapp](https://hub.docker.com/r/salrashid123/myapp/).  
     
and the source for my-rs.yaml and my-srv.yaml is listed below under [dockerimages/myapp](dockerimages/myapp).
   
* Get the service url
```
$ minikube service myapp-srv --url
http://host:port
```

* Verify application default credentials works
```
$ curl http://host:port/authz
<< you should see the email address associated with your gcloud >>
```

What the previous step shows is your replicaiton controller contacting the metadata server to return an access_token to the container.