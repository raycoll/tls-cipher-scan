import ssl
import socket
import sys
from subprocess import check_output

globendpoint = ""
globport = 0

def find_supported_ciphers(cipher_list, endpoint, port):
	supported_ciphers = []
	for cipher in cipher_list:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(10)
		try:
			ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=cipher)
		except ssl.SSLError as err:
			continue 
		try:
			ssl_sock.connect((endpoint, port))
		except ssl.SSLError as err: 
			continue
		else:
			cipher = ssl_sock.cipher()
			if cipher is not None:
				supported_ciphers.append(cipher[0])

	return supported_ciphers

# Comparator for sorted. Tries to negotiate with the tls endpoint with only c1 and c2 in the list of
# supported client ciphers. The cipher the server selects is considered "smaller"
# Naive approach, susceptible to transient failures in connecting/negotiating.
def cipher_cmp(c1, c2):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(10)
	# Openssl format
	ciphers = c1 + ":" + c2
	try:
		ssl_sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=ciphers)
	except ssl.SSLError as err:
		return 0
	try:
		ssl_sock.connect((globendpoint, globport))
	except ssl.SSLError as err: 
		return 0
	else:
		negotiated_cipher = ssl_sock.cipher()
		if negotiated_cipher is not None:
			if negotiated_cipher[0] == c1:
				return -1
			elif negotiated_cipher[0] == c2:
				return 1
		return 0

def find_server_prefs(supported_ciphers, endpoint, port):
	# Global needed for comparator
	global globendpoint
	global globport
	globendpoint = endpoint
	globport = port
	# "Sort" the ciphers
	return sorted(supported_ciphers, cmp=cipher_cmp)

def usage():
	print "cipher_pref_scan.py endpoint [port]"

def main(argv):
	if len(argv) < 1:
		usage()
		sys.exit(1)

	endpoint = argv[0]
	if len(argv) == 2:
		port = int(argv[1])
	else:
		port = 443
	
	print "Using " + str(ssl.OPENSSL_VERSION)
	print "Scanning " + endpoint + ":" + str(port)

	# python ssl doesn't provide a way to get a plain list of supported client ciphers. Call system openssl directly
	openssl_cipher_str = "DEFAULT"
	full_cipher_list = check_output(["openssl", "ciphers", openssl_cipher_str]).rstrip().split(":")
	print "Attempting all ciphers returned by: `openssl ciphers \"DEFAULT\"`...\n"

	supported_ciphers = find_supported_ciphers(full_cipher_list, endpoint, port)
	ordered_ciphers = find_server_prefs(supported_ciphers, endpoint, port)

	from pprint import pprint
	print endpoint + "'s supported ciphers:"
	pprint(supported_ciphers)
	print endpoint + "'s cipher preferences:"
	pprint(ordered_ciphers)

if __name__ == "__main__":
	main(sys.argv[1:])



