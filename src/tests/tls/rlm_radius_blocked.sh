#!/bin/sh
#
#  Check that the `radius` module pauses and resumes a RADIUS/TLS connection
#  when the connection blocks on write.
#
#  The home server is a Python program, which accepts one TLS connection and
#  stops reading.  rlm_radius_blocked.py runs the home server and radiusd, and
#  checks what radiusd does when the connection blocks.  Neither unit_test_tls
#  nor unit_test_bio takes part, so the test runs once.
#
#  "make test.tls" runs the test only when make found a Python interpreter, see
#  src/tests/tls/all.mk.
#
#  Environment:
#    PYTHON         the Python interpreter
#    RADIUSD        command which runs radiusd, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding rlm_radius_blocked.conf and the Python programs
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      dictionary directory
#    PORT           port of the home server
#    LPORT          UDP port where radiusd listens.  The port number is
#                   the same as PORT, as UDP and TCP ports are separate.
#
#  $Id$
#

LOG="$OUTPUT/rlm_radius_blocked.log"
RECEIPT="$OUTPUT/rlm_radius_blocked.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "rlm_radius_blocked.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export OUTPUT CONFDIR CERTDIR DICT_PATH PORT LPORT RADIUSD

if ! "$PYTHON" -I "$CONFDIR/rlm_radius_blocked.py" > "$LOG" 2>&1; then
	cat "$LOG"
	echo "--- $OUTPUT/rlm_radius_blocked_radiusd.log ---"
	cat "$OUTPUT/rlm_radius_blocked_radiusd.log"
	exit 1
fi

touch "$RECEIPT"
exit 0
