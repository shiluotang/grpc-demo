#!/usr/bin/env bash

openssl req -x509 -newkey rsa:2048 \
	-keyout key.pem \
	-out crt.pem \
	-sha256 \
	-days 36500 \
	-passout pass:123 \
	-subj '/C=CN/ST=Shanghai/L=Shanghai/O=MyCompany/OU=MyGroup/CN=www.xyz.com'
