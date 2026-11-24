#!/bin/sh
#
#  Make the test certificates in OUTDIR:
#
#    expired.pem	expired in 2000
#    future.pem		not valid until 2099
#    chain.pem		a valid certificate (valid.pem), then expired.pem
#
#  usage: certs.sh CA_CNF OUTDIR
#
#  On failure, the output of openssl is printed.
#
CNF=$1
OUT=$2
LOG="$OUT/openssl.log"

mkdir -p "$OUT"
: > "$LOG"

fail() {
	cat "$LOG"
	echo "Failed making the test certificates, see $LOG"
	exit 1
}

#
#  A self-signed certificate with the given dates.
#
selfsign() {
	: > "$OUT/index.txt"
	echo 01 > "$OUT/serial"

	TLS_CERT_OUT="$OUT" openssl req -new -newkey rsa:2048 -nodes -config "$CNF" -subj "/CN=$2" \
		-keyout "$OUT/$1.key" -out "$OUT/$1.csr" >> "$LOG" 2>&1 || fail

	TLS_CERT_OUT="$OUT" openssl ca -batch -selfsign -notext -config "$CNF" \
		-startdate "$3" -enddate "$4" \
		-keyfile "$OUT/$1.key" -in "$OUT/$1.csr" -out "$OUT/$1.pem" >> "$LOG" 2>&1 || fail
}

selfsign expired "Expired test certificate" 20000101000000Z 20000102000000Z
selfsign future "Future test certificate" 20990101000000Z 20991231000000Z

TLS_CERT_OUT="$OUT" openssl req -x509 -new -newkey rsa:2048 -nodes -config "$CNF" -subj "/CN=Valid test certificate" \
	-days 30 -keyout "$OUT/valid.key" -out "$OUT/valid.pem" >> "$LOG" 2>&1 || fail

cat "$OUT/valid.pem" "$OUT/expired.pem" > "$OUT/chain.pem"
