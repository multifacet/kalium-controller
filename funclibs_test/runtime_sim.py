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

    # sk = zmq_context.socket(zmq.REQ)
    # sk.connect("tcp://%s:%s" % (GUARD_IP, GUARD_PORT))
    # sk.send("%s:%s" % (event_name, data))

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect((GUARD_IP, GUARD_PORT))
    sk.send("%s:%s" % (event_name, data))

    resp = sk.recv(1024)
    return resp


def test0():
    event = {"test": "hello"}
    response = send_event(EVENT_GET, json.dumps({"meta":"cs.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:GET:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.facebook.com:GET:31.13.71.36:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response
    

def test1():
    event = {"test": "hello"}
    response = send_event(EVENT_GET, json.dumps({"meta":"cssssssss.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

def test2():
    event = {"test": "hello"}
    response = send_event(EVENT_GET, json.dumps({"meta":"cs.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"!!!!.wisc.edu:GET:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

def test3():
    event = {"test": "hello"}
    response = send_event(EVENT_GET, json.dumps({"meta":"cs.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:GET:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google1111.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

def test4():
    event = {"test": "hello"}
    response = send_event(EVENT_GET, json.dumps({"meta":"cs.wisc.edu:POST:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.wisc.edu:GET:99.84.127.56:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_SEND, json.dumps({"meta":"www.google.com:GET:8.8.8.8:80:1:%s" % (time.time()), "data":event}))
    print response
    response = send_event(EVENT_END, json.dumps({"meta":"function:0:0:0:0:%s" % (time.time()), "data":{}}))
    print response

if __name__ == '__main__':
    test0()
    test1()
    test2()
    test3()
    test4()


