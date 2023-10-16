#!/usr/bin/python


from google.cloud import storage
import google.auth

import google.auth.compute_engine
import google.auth.transport.requests

creds = google.auth.compute_engine.Credentials()
request = google.auth.transport.requests.Request()

session = google.auth.transport.requests.AuthorizedSession(creds)
r = session.get('https://www.googleapis.com/userinfo/v2/me').json()
print(str(r))


credentials, project = google.auth.default()    
client = storage.Client(credentials=credentials)
buckets = client.list_buckets()
for bkt in buckets:
  print(bkt)