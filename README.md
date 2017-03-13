# TLS Cipher Preference Scan
Finds the ciphers a TLS endpoint supports and infers its preferences

# Requirements
* Openssl in the script's PATH. Ideally 1.0.2+

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
Attempt to handshake using our client's full set of supported ciphers. Iterate and subtract the cipher selected by the
server in the previous iteration.

