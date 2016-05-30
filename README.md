# TLS Cipher Preference Scan
Finds the ciphers a TLS endpoint supports and infers its preferences

# Requirements
* Openssl, ideally 1.0.2. Using an older version will constrain the ciphers attempted
* python 2.7

# Usage
```cipher_pref_scan.py endpoint [port]```

# Example
```
python cipher_pref_scan.py www.google.com
Using OpenSSL 1.0.2h  3 May 2016
Scanning www.google.com:443 using all ciphers returned by: `openssl ciphers "DEFAULT"`...

www.google.com's supported ciphers:
['ECDHE-RSA-AES256-GCM-SHA384',
 'ECDHE-RSA-AES256-SHA384',
 'ECDHE-RSA-AES256-SHA',
 'AES256-GCM-SHA384',
 'AES256-SHA256',
 'AES256-SHA',
 'ECDHE-RSA-AES128-GCM-SHA256',
 'ECDHE-RSA-AES128-SHA256',
 'ECDHE-RSA-AES128-SHA',
 'AES128-GCM-SHA256',
 'AES128-SHA256',
 'AES128-SHA',
 'ECDHE-RSA-RC4-SHA',
 'RC4-SHA',
 'RC4-MD5',
 'DES-CBC3-SHA']
www.google.com's cipher preferences:
['ECDHE-RSA-AES128-GCM-SHA256',
 'ECDHE-RSA-AES128-SHA',
 'ECDHE-RSA-RC4-SHA',
 'AES128-GCM-SHA256',
 'AES128-SHA',
 'AES128-SHA256',
 'DES-CBC3-SHA',
 'RC4-SHA',
 'RC4-MD5',
 'ECDHE-RSA-AES256-GCM-SHA384',
 'ECDHE-RSA-AES128-SHA256',
 'ECDHE-RSA-AES256-SHA',
 'ECDHE-RSA-AES256-SHA384',
 'AES256-GCM-SHA384',
 'AES256-SHA',
 'AES256-SHA256']
```

# How?
Preferences are determined by "sorting" the endpoint's supported ciphers. The comparison function is a negotiation attempt with any two ciphers. The cipher that successfully negotiates with the server is considered "smaller".
This basic approach assumes that the TLS library used by the server is using "server preference". 
I.e. the server is using some static list of cipher suites that it iterates through until it finds one supported by the client.
