#!/usr/bin/python

##############
# 
# GCE Metadata Server Emulator
#
# https://cloud.google.com/compute/docs/storing-retrieving-metadata
#
# This script acts as a GCE's internal metadata server for local testing/emulation.
# The script performs the following:
#   * returns the access_token for your the gcloud CLI
#   * returns project information for your environment  
#   * return custom key-value attributes (either user-defined local or from the actual GCP project)
#
# *** NOTE: *** the access_token returned by this script to your app is for you gcloud client and is *LIVE*.
#               If you use this token in a script to simulate delete of your GCS bucket, you'll actually delete it!! 
#               You are free to acquire an access_token by any other means return that instead.
#                (eg. use a service account json file as shown here:
#                 https://github.com/salrashid123/gcpsamples/blob/master/auth/service/pyapp/service.py)  
#
# USAGE:
#  GCE's metadata server listens on host:port http://metadata.google.internal:80/ 
#  so to use this script you need to alter the host and listen on the privleged port 80
#  Since the script utilizes gcloud cli information which isnt' normally run as root, the following
#  instructions outlines how to port redirect from :80 --> :18080
#  You can achieve the prot redirect in any number of ways (especially since its http): iptables, socat, haproxy, nginx...
#  The example here uses socat
#
# add:
#    apt-get install socat
#
# edit:
# /etc/hosts
# 127.0.0.1       metadata metadata.google.internal
#
# run socat proxy:
# sudo socat TCP4-LISTEN:80,fork TCP4:127.0.0.1:18080
#
# add supporting libraries:
# cd gce_metadata_server/
# virtualenv env
# source env/bin/activate
# pip install -r requirements.txt
# 
# run test script either directly or with gunicorn
#  either run:
#     python gce_metadata_server.py
#  or:
#     gunicorn -b :18080 gce_metadata_server:app
# 
#  or if you run an app inside a docker container on your laptop that needs to access this, please be sure to enable
# host (--net=host) access/networking:
#   eg  docker run -p host_port:container_port --net=host -t <your_image> 
# You can extend this sample for any arbitrary metadta you are interested in emulating (eg, disks, hostname, etc).
# Simply make an @app.route()  for the path and either use the gcloud wrapper or hardcode the response you're interested in

# TODO List:
#   * implement cache for key-value pairs and access_token
#       (i.,e no need to keep refreshing the token...its already valid 
#       (can check for access_token validty by calling https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=)

from flask import Flask
from flask import request, Response, render_template, jsonify
from werkzeug.wrappers import Request
from jinja2 import Template, Environment, FileSystemLoader
import json
import os, logging, sys
import urllib2
from gcloud_wrapper import GCloud

app = Flask(__name__)

# this is the `gcloud config configurations list` settings to use.
# override this variable if you would rather create a new configuration specific
# to local testing (eg, for a service_account file that you enabled on gcloud)
gcloud_configuraiton = 'default'

# dict of custom attributes to return
# If you would rather use the *live* metadata key value pairs setup for your project, see
#  __setupProjectMetadata() below
custom_attributes = { 'mykey1': 'myvalue1' }

logFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)           
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logFormatter)
logger.addHandler(ch)

# middleware class which checks all requests if the Metadata-Flavor: Google header is present and if
# the Host: header is correct.  If it is not correct, return an error response similar to what GCE does itself
class TransitMiddleWare(object):
  def __init__(self, app):
     self.app = app

  def __call__(self, environ, start_response):
    req = Request(environ, shallow=True)  
    host = req.headers.get('Host')
    if host not in ('metadata.google.internal', '169.254.169.254' , 'metadata'):
      status = '403 Forbidden'
      response_headers = [('Content-Type','text/html; charset=UTF-8')]
      start_response(status, response_headers)
      return ['Host Header nust be one of (metadata.google.internal, metadata, 169.254.169.254)']
    req_path = environ.get('PATH_INFO')
    metadata_flavor = req.headers.get('Metadata-Flavor')
    if (metadata_flavor is None and req_path != '/'):
      status = '403 Forbidden'
      response_headers = [('Content-Type','text/html; charset=UTF-8')]
      start_response(status, response_headers)
      logging.error("Metadata-Flavor: Google header not sent for: " + environ.get('PATH_INFO'))
      t = Template('''<p>Your client does not have permission to get URL 
      <code>{{ err_path }}</code> from this server. Missing Metadata-Flavor:Google header. ''')
      return [str(t.render(err_path= environ.get('PATH_INFO')))]
    return self.app(environ, start_response)


# Make sure every response has these headers (which is what gce does)
@app.after_request
def add_meta_headers(response):
    response.headers['Server'] = 'Metadata Server for VM'
    response.headers['Metadata-Flavor'] = 'Google'    
    return response

# hello world
# some gcp libraries checks the root path '/' on the metadata server for some reason...
@app.route('/')
def index():
    return 'hello world', 200, {'Content-Type': 'text/plain; charset=utf-8'}

# return the access_token that your local gcloud provides
# NOTE: this access token is live,
@app.route('/computeMetadata/v1/instance/service-accounts/<string:acct>/<string:k>', methods = ['GET'])
def getDefaultServiceAccount(acct,k):
    logging.info('Requesting ServiceAccount : ')    
    result = GCloud(['--configuration', gcloud_configuraiton, 'auth','print-access-token','--format','json()'])
    token = json.loads(result)
    logging.info('access_token: ' + token)     
    r = urllib2.urlopen("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + token).read()
    r = json.loads(r)
    logging.info (r)
    if (k=='aliases'):
        return acct
    elif (k=='email'):
        return r['email']
    elif (k=='scopes'):
        sret = ''
        for s in r['scope'].split(' '):
           sret = sret + '\n' + s
        resp = Response(sret, status=200, mimetype='text/plain')
        return resp
    elif (k=='token'):
        f = {"access_token": token,"expires_in":3600,"token_type":"Bearer"}
        return jsonify(**f)
    logging.info('Unknown service-account path Request')
    resp = Response("Unknown service-account path", status=500, mimetype='text/plain')
    return resp

# return a couple of sample, well known attributes like project-id and number
@app.route('/computeMetadata/v1/project/project-id', methods = ['GET'])
def getProjectID():
    logging.info('Requesting project_id: ')  
    result = GCloud(['--configuration', gcloud_configuraiton, 'config','list','--format','json()'])
    p = json.loads(result)
    logging.info('Requesting project-id: ' +  p['core']['project'])
    return p['core']['project']

@app.route('/computeMetadata/v1/project/numeric-project-id', methods = ['GET'])
def getNumericProjectID():
    logging.info('Requesting numeric project_id: ')
    # gcloud --configuration default config list --format 'json()'
    result = GCloud(['--configuration', gcloud_configuraiton, 'config','list','--format','json()'])
    p = json.loads(result)
    projectId = p['core']['project']
    # gcloud --configuration default projects list --format 'value(projectNumber)' --filter 'projectId=current_projectId''
    result = GCloud(['--configuration', gcloud_configuraiton, 'projects','list','--format','value(projectNumber)',"--filter", "projectId=" + projectId])
    p = json.loads(result)
    logging.info("Current numberic ID:" + str(p))
    return str(result)

# return arbitary user-defined key-value pairs
@app.route('/computeMetadata/v1/project/attributes/<string:k>', methods = ['GET'])
def getCustomMetadata(k):
    logging.info('Requesting custom_metadata: ' +  k )
    resp = Response()    
    try:
      resp.headers['Content-Type'] ='application/text'
      v = custom_attributes[k]
    except KeyError:
      resp.headers['Content-Type'] = 'text/html; charset=UTF-8'
      t = Template('''<p>The requested URL <code>{{ err_path }}</code> was not found on this server.  
         <ins>Thats all we know.Thats all we know.</ins>''')
      return str(t.render(err_path=request.path))
    return v

# Optional method to initialize the scritp with your projects *live* metadata key-value pairs
def __setupProjectMetadata():
    logging.info('Settting up  project metadata: ')  
    result = GCloud(['--configuration', gcloud_configuraiton, 'compute','project-info','describe', '--format','json()'])
    p = json.loads(result)
    for item in p['commonInstanceMetadata']['items']:
        if (item['key']!='sshKeys'):
          custom_attributes[item['key']] = item['value']          
    logging.info('Enabled the following custom attributes ' + str(custom_attributes))

if __name__ == '__main__':
  app.wsgi_app = TransitMiddleWare(app.wsgi_app)
  app.run(host='0.0.0.0', port=18080, debug=False)
