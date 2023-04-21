#!/usr/bin/env python3

import requests
import argparse
import sys

parser = argparse.ArgumentParser()
# connection
parser.add_argument("-H", dest="host", default=None)
parser.add_argument("-P", dest="port", type=int, default=25)

# auth
parser.add_argument("-u", dest="user", default=None)
parser.add_argument("-p", dest="passwd", default=None)

# gophish
parser.add_argument("-k", dest="key", default=None)
parser.add_argument("-f", dest="froms", default=None)

arguments = parser.parse_args()

if not arguments.host:
	sys.stderr.write("No host was specified\n")
	sys.exit(-1)

if not arguments.key:
	sys.stderr.write("No API key was specified\n")
	sys.exit(-1)

if not arguments.froms:
	sys.stderr.write("From addresses are required\n")
	sys.exit(-1)

url = "http://127.0.0.1:3333/api/smtp/"

existing_entries = requests.get(url, headers={"Authorization": arguments.key}).json()

froms = [x.strip() for x in arguments.froms.split(",")]
for f in froms:
	f = f.lower()
	has_from = len(existing_entries) and f in [r["from_address"] for r in existing_entries]
	if has_from:
		continue

	payload = {
		"name": f.split("@")[0],
		"host": arguments.host,
		"interface_type": "SMTP",
		"from_address": f,
		"ignore_cert_errors": True
	}

	if arguments.user and arguments.passwd:
		payload["username"] = arguments.user
		payload["password"] = arguments.passwd

	requests.post(url, headers={"Authorization": arguments.key}, json=payload).json()
	print("Added user: %s" % f)