#!/bin/sh

CERTS=$(dirname $0)/../../../raddb/certs

cd $(CERTS)

#
#  Create a new server certificate from the existing config
#
openssl req -new  -out server.csr -key server.key -configs server.cnf

openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12  -passin pass:`grep output_password server.cnf | sed 's/.*=//;s/^ *//'` -passout pass:`grep output_password server.cnf | sed 's/.*=//;s/^ *//'`

openssl pkcs12 -in server.p12 -out server.pem -passin pass:`grep output_password server.cnf | sed 's/.*=//;s/^ *//'` -passout pass:`grep output_password server.cnf | sed 's/.*=//;s/^ *//'`
