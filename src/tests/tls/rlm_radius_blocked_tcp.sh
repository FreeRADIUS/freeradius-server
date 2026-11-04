#!/bin/sh
#
#  Check that the `radius` module pauses and resumes a RADIUS/TCP connection
#  when the connection blocks on write.
#
#  This is the plain TCP version of rlm_radius_blocked.sh.  The test runs the
#  same Python programs, with TRANSPORT=tcp.  The home server accepts one
#  connection and stops reading.
#
#  "make test.tls" runs the test only when make found a Python interpreter, see
#  src/tests/tls/all.mk.
#
#  Environment:
#    PYTHON         the Python interpreter
#    RADIUSD        command which runs radiusd, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding rlm_radius_blocked_tcp.conf and the Python programs
#    DICT_PATH      dictionary directory
#    PORT           port of the home server
#    LPORT          UDP port where radiusd listens.  The port number is
#                   the same as PORT, as UDP and TCP ports are separate.
#
#  $Id$
#

LOG="$OUTPUT/rlm_radius_blocked_tcp.log"
RECEIPT="$OUTPUT/rlm_radius_blocked_tcp.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

export OUTPUT CONFDIR CERTDIR DICT_PATH PORT LPORT RADIUSD
export TRANSPORT=tcp

if ! "$PYTHON" -I "$CONFDIR/rlm_radius_blocked.py" > "$LOG" 2>&1; then
	cat "$LOG"
	echo "--- $OUTPUT/rlm_radius_blocked_tcp_radiusd.log ---"
	cat "$OUTPUT/rlm_radius_blocked_tcp_radiusd.log"
	exit 1
fi

touch "$RECEIPT"
exit 0
