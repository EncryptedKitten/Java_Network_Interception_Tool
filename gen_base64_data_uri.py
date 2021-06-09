import base64, requests, sys

if (len(sys.argv) == 2):
	url = sys.argv[1]
else:
	# Put the URL of the file you want to encode as the command line argument or make it this string here.
	url = "http://1.0.0.127.in-addr.arpa/yggdrasil_session_pubkey.der"

r = requests.get(url)

if "Content-Type" in r.headers:
	mime = r.headers["Content-Type"]
elif r.url.endswith("der"):
	mime = "application/x-x509-ca-cert"
elif r.url.endswith("json"):
	mime = "application/json"
else:
	mime = "application/octet-stream"

r_data = "data:" + mime + ";base64," + base64.b64encode(r.content).decode()

print(r_data)