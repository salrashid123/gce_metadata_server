#!/usr/bin/python

from flask import Flask
from flask import Response

import dns.resolver

import httplib2
from apiclient.discovery import build
from oauth2client.client import GoogleCredentials
from oauth2client.client import ApplicationDefaultCredentialsError
from google.cloud import storage
import google.auth


import os
from os import listdir
from os.path import isfile, join

app = Flask(__name__)

@app.route('/')
@app.route('/_ah/health')
def default():
  return 'ok'

@app.route('/varz')
def get_env():
  r = ''
  for key in os.environ.keys():
    r = r +  key + ' --> ' + os.environ[key] + '\n'
  return Response(r, mimetype='text/plain')

@app.route('/filez')
def get_files():
  r = ''
  mypath='/apps/html'
  onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
  for a in  onlyfiles:
   r = r + '\n' + a
  return Response(r, mimetype='text/plain')

@app.route('/authz')
def authcheck():

    scope='https://www.googleapis.com/auth/userinfo.email'
    try: 
      credentials = GoogleCredentials.get_application_default()
      if credentials.create_scoped_required():
        credentials = credentials.create_scoped(scope)
    except ApplicationDefaultCredentialsError:
      return "Unable to acquire application default credentials"

    http = httplib2.Http()
    credentials.authorize(http)

    service = build(serviceName='oauth2', version= 'v2',http=http)
    resp = service.userinfo().get().execute()
    return resp['email']

@app.route('/gcloudauthz')
def gcloudauthcheck():

  credentials, project = google.auth.default()    
  client = storage.Client(credentials=credentials)
  buckets = client.list_buckets()
  r = 'bucket names'
  for bkt in buckets:
    r = r + bkt.name + '\n'
  return r

@app.route('/hostz')
def get_host():
  r = ''
  try: 
    # srv
    answers = dns.resolver.query('_my-srv-port._tcp.myapp-srv.default.svc.cluster.local', 'SRV')
    if answers is not None:
      for rdata in answers:
        r= r + str(rdata)
  except dns.resolver.NXDOMAIN as e:
    r = 'DNS value not found  ' + str(e)
  except dns.exception.DNSException:
    r = "Unhandled exception"           

  try:
    # petset
    answers = dns.resolver.query('myapp-srv.default.svc.cluster.local', 'SRV')  
    if answers is not None:
      for rdata in answers:
        r= r + str(rdata)
  except dns.resolver.NXDOMAIN as e:
    r = 'DNS value not found  ' + str(e)
  except dns.exception.DNSException:
    r = "Unhandled exception"    

  return Response(r, mimetype='text/plain')  

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080, debug=True)    
