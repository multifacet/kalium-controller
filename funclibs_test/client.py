import sys

import socket

import json
import urllib2
import subprocess
import json
import time
# import boto3
# import botocore
from conf import *

import os
import errno

import zmq

zmq_context = zmq.Context()

def send_event(event_name, data):

    sk = zmq_context.socket(zmq.REQ)
    sk.connect("tcp://%s:%s" % (GUARD_IP, GUARD_PORT))
    sk.send("%s:%s" % (event_name, data))
    resp = sk.recv()
    return resp


def lambda_handler(event, context):
    
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

def lambda_handler2(event, context):
    
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

def lambda_handler3(event, context):
    
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

if __name__ == '__main__':
    event = {"test": "hello"}
    # lambda_handler(event, None)
    # lambda_handler2(event, None)
    # lambda_handler3(event, None)
    response = send_event(EVENT_GET, json.dumps({"meta":"cs.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:GET:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    # response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    # print response
    # response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    # print response
    # response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    # print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response
    
