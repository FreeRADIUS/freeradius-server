#!/bin/sh
#
#  Create a client certificate of more than 65000 octets for the
#  `tls-big-client-cert` test.
#
#  The certificate has one private extension, which holds 65000 octets of
#  filler.  The script signs the certificate with the test certificate
#  authority (CA) in `raddb/certs/rsa`.  The script does not mark the
#  extension critical.
#
#  Usage: big_client_cert.sh <output directory>
#
#  The script writes `client.key` and `client.pem` into the output directory.
#
#  $Id$
#
set -e

OUT="$1"
CERTDIR=raddb/certs/rsa

mkdir -p "$OUT"

{
	echo "[big]"
	echo "basicConstraints = CA:FALSE"
	echo "extendedKeyUsage = clientAuth"
	printf "1.3.6.1.4.1.11344.255.1 = ASN1:FORMAT:HEX,OCTETSTRING:"
	head -c 65000 /dev/zero | od -An -v -tx1 | tr -d ' \n'
	echo
} > "$OUT/client.ext"

openssl req -new -newkey rsa:2048 -nodes -keyout "$OUT/client.key" -out "$OUT/client.csr" \
	-subj "/C=FR/ST=Radius/O=Example Inc/CN=Example big user" > "$OUT/openssl.log" 2>&1

openssl x509 -req -in "$OUT/client.csr" -CA "$CERTDIR/ca.pem" -CAkey "$CERTDIR/ca.key" \
	-passin pass:whatever -CAcreateserial -CAserial "$OUT/client.srl" -days 2 \
	-extfile "$OUT/client.ext" -extensions big -out "$OUT/client.pem" >> "$OUT/openssl.log" 2>&1
