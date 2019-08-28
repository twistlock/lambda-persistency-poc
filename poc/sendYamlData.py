#!/usr/bin/env python3
from sys import argv
import requests
import json


LAMBDA_ADDR=r"" # fill in


def main(argv):
	if len(argv) != 2:
		print("[+] Usage: {} <yaml-file-to-send>".format(argv[0]))
		return

	if not LAMBDA_ADDR:
		print("[!] The LAMBDA_ADDR variable isn't defined, overwrite me!")
		return

	filepath = argv[1]

	try:
		with open(filepath, "r") as yaml_file:
			content = yaml_file.read()
	except FileNotFoundError:
		print("[+] File {} doesn't exist".format(filepath))
		return

	send_data_print_resp(LAMBDA_ADDR, content)





def send_data_print_resp(lambda_addr, data):
	post_data = {"yamlData": data}
	response = requests.post(lambda_addr, json=post_data)


	decoded = response.content.decode('utf8')
	try:
		data = json.loads(decoded)
		if "body" in data:
			data = data["body"]
			if type(data) != dict:
				data = json.loads(data)
	except json.decoder.JSONDecodeError as e:
		print(decoded)
		print("[!] send_command: Lambda response body isn't JSON decodeable. \nError: {}\nReceived data: {}".format(str(e), decoded))

	print(data)




if __name__ == "__main__":
	main(argv)