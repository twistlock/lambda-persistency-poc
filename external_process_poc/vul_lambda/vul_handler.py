#!/usr/bin/env python3 

import os
import json


def handler(event, context):
	print(event)
	if "body" in event:
		event = event["body"]

	cmd = "echo -n {} | base64".format(event)
	b64_encoded = os.popen(cmd).read()

	if not b64_encoded:
		b64_encoded = "Empty"
		
	return build_response(b64_encoded)


def build_response(data):
	response = {
		"isBase64Encoded": False,
		"statusCode" : 200,
		"headers" : {"Content-Type" : "text/plain"},
		"body" : json.dumps({"output" : data})
	}
	return response 
