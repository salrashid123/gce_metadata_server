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
# add network alias interface for metadata server by IP address
#
# sudo ifconfig lo:0 169.254.169.254 up
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
# host (--net=host) or bridge (--net=bridge) access/networking:
#   eg  docker run -t --net=bridge --add-host metadata.google.internal:169.254.169.254 --add-host metadata:169.254.169.254 compute
# or
#   eg  docker run -p host_port:container_port --net=host -t <your_image> 
# You can extend this sample for any arbitrary metadta you are interested in emulating (eg, disks, hostname, etc).
# Simply make an @app.route()  for the path and either use the gcloud wrapper or hardcode the response you're interested in

from flask import Flask
from flask import request, Response, render_template, jsonify
from werkzeug.wrappers import Request
from jinja2 import Template, Environment, FileSystemLoader
import json
import os, logging, sys, time, datetime, getopt
from time import mktime
from datetime import datetime
import calendar
import urllib2
from cStringIO import StringIO

from gcloud_wrapper import GCloud

app = Flask(__name__)

# this is the `gcloud config configurations list` settings to use.
# override this variable if you would rather create a new configuration specific
# to local testing (eg, for a service_account file that you enabled on gcloud)
gcloud_configuraiton = 'default'

# If for whatever reason gcloud client isn't setup, this script will read the follwoing Environment
# variables and return its value for the access_token, proejctID and numeric projectID
# see __getStaticMetadataValue
GOOGLE_PROJECT_ID = 'GOOGLE_PROJECT_ID'
GOOGLE_NUMERIC_PROJECT_ID = 'GOOGLE_NUMERIC_PROJECT_ID'
GOOGLE_ACCESS_TOKEN = 'GOOGLE_ACCESS_TOKEN'

# dict of custom attributes to return
# If you would rather use the *live* metadata key value pairs setup for your project, see
#  __setupProjectMetadata() below
custom_attributes = { 'mykey1': 'myvalue1' }

# dict to hold cached objects (token, projectId, etc)
cache = {}

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

# hack: gsutil makes this special request
@app.route('/computeMetadata/v1/instance/service-accounts', methods = ['GET'])
def getServiceAccountListRedirect():
   return redirect("/computeMetadata/v1/instance/service-accounts/", code=301)

# hack: list service accounts that are active...since we use gsutil in default configuration, 
# i'm just going to consider displaying the default only because the way this script is coded,
# i use the --configuration and its default identity...
@app.route('/computeMetadata/v1/instance/service-accounts/', methods = ['GET'])
def getServiceAccountList():
    logging.info('Requesting Service Account List' )
    resp = Response()
    resp.headers['Content-Type'] ='application/text'
    return 'default/'

@app.route('/computeMetadata/v1/instance/service-accounts/<string:acct>/', methods = ['GET'])
def getDefaultServiceList(acct):
  logging.info('Returning default list')
  getDefaultServiceAccount(acct,'token')
  ret = {}
  ret['aliases'] = acct
  ret['email'] = cache['email']
  ret['scopes'] = cache['scopes']
  return jsonify(ret), 200

# return the access_token that your local gcloud provides
# NOTE: this access token is live,
@app.route('/computeMetadata/v1/instance/service-accounts/<string:acct>/<string:k>', methods = ['GET'])
def getDefaultServiceAccount(acct,k):
    logging.info('Requesting ServiceAccount : ' + acct + '/' +k )

    # check if the access_token is still valid.  If it is, return from cache but first decrement
    # the expires_in field for the remaining time.  For all other attributes, return as-is
    try:
       p = cache[k]
       if (k=='token'):
         key_expire_at = cache['token_valid_until']
         if (int(calendar.timegm(time.gmtime()) >= key_expire_at)):     
            logging.info('access_token expired')
         else:
            token_val = cache[k]
            seconds_still_valid = key_expire_at - int(calendar.timegm(time.gmtime()))
            logging.info('token still valid for ' + str(seconds_still_valid) )
            token_val['expires_in']=seconds_still_valid
            return jsonify(**token_val)
       else:
         return str(p)
    except KeyError as e:
       logging.info( k + ' not found in cache, refreshing..') 

    # First acquire gcloud's access_token
    try:
        token = (GCloud(['--configuration', gcloud_configuraiton, 'auth','print-access-token'])).rstrip()
    except:
        logging.error("gcloud not initialized, attempting to return static access_token from environment")
        token = __getStaticMetadataValue(GOOGLE_ACCESS_TOKEN)
    logging.info('access_token: ' + token)
    try:
        # and then ask the token_info endpoint for details about it.
        r = urllib2.urlopen("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + token).read()
        r = json.loads(r)
        
        cache['aliases'] = acct
        cache['email'] = r['email']
        cache['scopes'] = ("\n".join(r['scope'].split(' ')))

        valid_for = r['expires_in']
        key_expire_at = int(calendar.timegm(time.gmtime()) + int(valid_for))
        cache['token_valid_until'] = key_expire_at
        f = {"access_token": token,"expires_in": int(valid_for) ,"token_type":"Bearer"}
        cache['token'] = f

        if (k == 'token'): 
            return jsonify(**f)
        else:
          return cache[k]
    except:
        logging.error("Unable to interrogate tokeninfo endpoint for token details; bailing..")
        # TODO:  we could try to fake a response (eg, while running this in disconnected mode...but lets just bail for now
        return "Unable to acquire access_token", 500

# return a couple of simple, well known attributes like project-id and number
@app.route('/computeMetadata/v1/project/project-id', methods = ['GET'])
def getProjectID():
    logging.info('Requesting project_id')
    try:
       p = cache['project-id']
       return str(p)
    except KeyError as e:
       logging.info('project-id not found, refreshing..')    
    result = GCloud(['--configuration', gcloud_configuraiton, 'config','list','--format','json()'])
    p = json.loads(result)
    try: 
        logging.info('Returning project-id: ' +  p['core']['project'])
        cache['project-id'] =  p['core']['project']
        return p['core']['project']
    except KeyError as e:
        logging.info('project-id not found or not set in gcloud')
        return __getStaticMetadataValue(GOOGLE_PROJECT_ID)

@app.route('/computeMetadata/v1/project/numeric-project-id', methods = ['GET'])
def getNumericProjectID():
    logging.info('Requesting numeric project_id: ')
    try:
       p = cache['numeric-project-id']
       return str(p)
    except KeyError as e:
       logging.info('numeric-project-id not found, refreshing..')
    result = GCloud(['--configuration', gcloud_configuraiton, 'config','list','--format','json()'])
    p = json.loads(result)
    try:
        projectId = p['core']['project']
        result = GCloud(['--configuration', gcloud_configuraiton, 'projects','list','--format','value(projectNumber)',"--filter", "projectId=" + projectId])
        logging.info("Returning numeric project_id:" + str(result))
        cache['numeric-project-id'] = str(result)
        return str(result)
    except KeyError as e:
       logging.info('numeric-project-id not found or not set in gcloud') 
       return __getStaticMetadataValue(GOOGLE_NUMERIC_PROJECT_ID)   

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

# Optional method to initialize the script with your projects *live* metadata key-value pairs
def __setupProjectMetadata():
    logging.info('Settting up  project metadata: ')  
    result = GCloud(['--configuration', gcloud_configuraiton, 'compute','project-info','describe', '--format','json()'])
    p = json.loads(result)
    for item in p['commonInstanceMetadata']['items']:
        if (item['key']!='sshKeys'):
          custom_attributes[item['key']] = item['value']          
    logging.info('Enabled the following custom attributes ' + str(custom_attributes))

# Optional method to acquire the access_token from an instance in your project (requires gcloud or curl installed on your GCE instance)
# TODO: the remote ssh writes to stdout and would need to capture it.  For now, I left it as-is, unimplemented :(
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

    logging.info('Acquired access_token from instance ' + instance)    

# Lookup environment variables incase gcloud cli isn't setup'
def __getStaticMetadataValue(k):
    logging.info('Returning static value for key ' + k)
    try:
        v = os.environ[k]
        return v
    except KeyError as e:
       logging.info('Static value not found, returning null')
       return  "Static Key not found " + k    
    

if __name__ == '__main__':
  host='0.0.0.0'
  port=18080
 
  myopts, args = getopt.getopt(sys.argv[1:],"h:p:")
 
  for o, a in myopts:
    if o == '-h':
        host=a
    elif o == '-p':
        port=a

  app.wsgi_app = TransitMiddleWare(app.wsgi_app)
  app.run(host=host, port=port, debug=False)
