#!/usr/bin/python

import os
import sys
import string
import subprocess

GCLOUD_PATH = None

for path in string.split(os.environ['PATH'], os.pathsep):
    candidate = os.path.join(path, 'gcloud')
    if os.path.exists(candidate): 
        GCLOUD_PATH =  os.path.abspath(candidate)
        break

if GCLOUD_PATH == None:
	print "The gcloud command must be in your PATH someplace for this to work"
	exit(-1)
 

def GCloud(_args):
  args = ['gcloud'] + _args
  process = subprocess.Popen(args, stdout=subprocess.PIPE)
  out, err = process.communicate()
  return out
