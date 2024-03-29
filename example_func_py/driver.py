import sys
sys.path.insert(0, "/var/task/")
# del sys.modules["socket"]
# del sys.modules["ssl"]

if "ssl" in sys.modules:
	del sys.modules["ssl"]

# import socket1 as socket
# 
import func
import json
import urllib2
import subprocess
import json
import time
import boto3
import botocore
from conf import *

import os
import errno

# from reader import monitor, listener

import threading




def remove_tag(event):
	tag = ""
	body = event
	if "tag" in event:
		tag = event["tag"]
		body = event["body"]
	return tag, body


def add_tag(event, dur=None):
	if dur:
		return {"tag": os.environ['AWS_LAMBDA_FUNCTION_NAME'], "body":event, "dur": dur}
	return {"tag": os.environ['AWS_LAMBDA_FUNCTION_NAME'], "body":event}


def lambda_handler(event, context):
	event = {"test": "hello"}
	res = func.main(event, context)
	return res


if __name__ == '__main__':
    lambda_handler({"test":1}, None)
