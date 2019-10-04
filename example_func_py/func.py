import json
import urllib2
import subprocess
import json
import time
import boto3
import socket
from conf import *

def send_event(event_name, data):

	# sk = zmq_context.socket(zmq.REQ)
	# sk.connect("tcp://%s:%s" % (GUARD_IP, GUARD_PORT))
	# sk.send("%s:%s" % (event_name, data))

	sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sk.connect((GUARD_IP, GUARD_PORT))
	sk.send("%s:%s" % (event_name, data))

	resp = sk.recv(1024)
	return resp

def main(event, context):
	response = urllib2.urlopen('https://www.cs.wisc.edu/', data=None)
	response = urllib2.urlopen('https://www.wisc.edu/', data=None)
	response = urllib2.urlopen('https://www.google.com/', data=None)
