import os
import yaml
import io
from contextlib import redirect_stdout
import json

"""
* Real Handler  
"""
def Handler(event, context):
	if "body" in event:
		event = event["body"]
		if type(event) != dict:
			try:
				event = json.loads(event)
			except json.decoder.JSONDecodeError as e:
				return build_response({"Status": "Error", "Data": "Request body isn't json decodable: " + repr(e)})
	
	
	if "yamlData" not in event:
		return build_response({"Status": "Error", "Data": "Request body doesn't contain 'yamlData'"})

			
	yaml_data = event["yamlData"]
	print("[+] handler: Parsing yaml data...")
	ret = yaml.load(yaml_data)

	return build_response({"Status": "Success"})




def build_response(data):
	response = {
		"isBase64Encoded": False,
		"statusCode" : 200,
		"headers" : {"Content-Type" : "text/plain"},
		"body" : json.dumps(data)
	}
	return response 
