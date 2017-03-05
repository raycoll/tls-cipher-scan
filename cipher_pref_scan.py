import sys
import subprocess
import os

def get_negotiated_cipher(ciphers, endpoint, port):
    with open(os.devnull, 'w') as devnull:
        s_client_cmd = ["openssl", "s_client", "-connect", str(endpoint) + ":" + str(port), "-cipher", ciphers]
        s_client = subprocess.Popen(s_client_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=devnull)
        cipher_filter = subprocess.Popen(["grep 'Cipher .* :' | cut -d ':' -f2"], stdin=s_client.stdout,
                stdout=subprocess.PIPE, shell=True)
        s_client.stdin.write("Q")
        return cipher_filter.stdout.readline()

def find_supported_ciphers(cipher_list, endpoint, port):
    supported_ciphers = []
    for cipher in cipher_list:
        if cipher in get_negotiated_cipher(cipher, endpoint, port):
            supported_ciphers.append(cipher)

    return supported_ciphers

def find_server_prefs(supported_ciphers, endpoint, port):
    server_prefs = []
    remaining_ciphers = list(supported_ciphers)
    for x in range(0, len(remaining_ciphers)):
        negotiated_cipher = get_negotiated_cipher(':'.join(remaining_ciphers), endpoint, port).strip()
        if negotiated_cipher in remaining_ciphers:
            server_prefs.append(negotiated_cipher)
            remaining_ciphers.remove(negotiated_cipher)

    return server_prefs

def usage():
        print("cipher_pref_scan.py endpoint [port]")

def main(argv):
    if len(argv) < 1:
        usage()
        sys.exit(1)

    endpoint = argv[0]
    if len(argv) == 2:
        port = int(argv[1])
    else:
        port = 443

    # python ssl doesn't provide a way to get a plain list of supported client ciphers. Call system openssl directly
    openssl_cipher_str = "DEFAULT"
    full_cipher_list = subprocess.check_output(["openssl", "ciphers", openssl_cipher_str]).rstrip().split(":")
    openssl_version_str = subprocess.check_output(["openssl", "version"])

    print("Using " + str(openssl_version_str))
    print("Scanning " + endpoint + ":" + str(port) + " using all ciphers returned by: `openssl ciphers \"DEFAULT\"`...\n")

    supported_ciphers = find_supported_ciphers(full_cipher_list, endpoint, port)
    ordered_ciphers = find_server_prefs(supported_ciphers, endpoint, port)

    from pprint import pprint
    print(endpoint + "'s supported ciphers:")
    pprint(supported_ciphers)
    print(endpoint + "'s cipher preferences(assuming server preference):")
    pprint(ordered_ciphers)

if __name__ == "__main__":
    main(sys.argv[1:])

