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
	os.environ['PATH'] = os.environ['PATH'] + ':' + os.environ['LAMBDA_TASK_ROOT']
	print os.environ['PATH']
	r = os.popen("ps aux").read()
	if "./guard" not in r:
		try:
			print "start new guard"
			proc = subprocess.Popen(["./guard"], stderr=subprocess.PIPE)
			time.sleep(1)
		except:
			pass
	event = {"test": "hello"}
	res = func.main(event, context)

	# os.popen("killall -9 guard").read()
	# time.sleep(1)
	return res


# if __name__ == '__main__':
#     lambda_handler({"test":1}, None)
