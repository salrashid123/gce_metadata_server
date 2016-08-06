#!/usr/bin/python
##############
#
# gcloud CLI wrapper - without re-invoking Python
#
# author: rensin@
#
##############

import os
import sys
import string

# need to setup a few path items so the modules find the right
# bits

GCLOUD_PATH = None

for path in string.split(os.environ['PATH'], os.pathsep):
    candidate = os.path.join(path, 'gcloud')
    if os.path.exists(candidate): 
        GCLOUD_PATH =  os.path.abspath(candidate)
        break

if GCLOUD_PATH == None:
	print "The gcloud command must be in your PATH someplace for this to work"
	exit(-1)
 
if os.path.islink(GCLOUD_PATH):
    GCLOUD_PATH = os.path.realpath(GCLOUD_PATH)

SDK_PATH = os.path.dirname(os.path.dirname(GCLOUD_PATH)) + '/lib/'

sys.path.insert(0, SDK_PATH)

_GCLOUD_PY_DIR = os.path.dirname(SDK_PATH)
_THIRD_PARTY_DIR = os.path.join(_GCLOUD_PY_DIR, 'third_party')

if os.path.isdir(_THIRD_PARTY_DIR):
  sys.path.insert(0, _THIRD_PARTY_DIR)

# the gcloud code captures STDOUT as soon as the gcloud_main
# module is loaded. So... If we want to be able to work with
# the output of the gcloud command, we have to capture STDOUT
# first!

from StringIO import StringIO

STDOUT = sys.stdout         # save the original STDOUT
GCLOUD_OUTPUT = StringIO()  # create a new file object
sys.stdout = GCLOUD_OUTPUT  # set stdout to the new object

# load the key module. it will capture what
# it thinks is stdout, but is really the new
# file object we setup.

import googlecloudsdk.gcloud_main

sys.stdout = STDOUT # restore the old stdout so 'print' works

# gcloud exports a VERY handy object named CLI
# that does 99% of our heavy lifting. Yay!
# 
# So let's grab an instance of that and keep 
# it around for our use

_CLI = googlecloudsdk.gcloud_main.CreateCLI([])

# This is a little wrapper function that invokes the cli
# with your arguments and then returns the output
# as a simple string

def GCloud(_args):
	_CLI.Execute(args=_args)
	output = GCLOUD_OUTPUT.getvalue()
	GCLOUD_OUTPUT.truncate(0);
	return output
