#!/bin/sh
#
#  Check that the `radius` module, in `mode = dynamic-proxy`, can open a
#  Transport Layer Security (TLS) connection to a destination that
#  a request names.  The module cannot open the connection when the server
#  starts, because the destination is only known when a request runs the
#  `%home.sendto.ipaddr()` expansion.
#
#  unit_test_tls is the home server, as in `rlm_radius.sh`.  Because
#  unit_test_tls does not handle RADIUS packets, the test covers the
#  connection and the handshake, and does not get a reply.
#
#  Once unit_test_tls is listening, unit_test_tls runs the command that the
#  `-e` option receives.  The command does the following:
#
#    1. Runs radiusd with `rlm_radius_tls_dynamic.conf`, and waits until
#       radiusd logs that radiusd is ready.
#    2. Runs `rlm_radius_dtls_dynamic.py`, which sends one Access-Request
#       over UDP to radiusd.
#    3. Reads the output of radiusd through a named pipe.
#    4. Stops radiusd when the output says that the TLS connection is open
#       or that the TLS connection failed.
#
#  The request runs the expansion, and the `radius` module opens a TLS
#  connection to unit_test_tls.  Because the read blocks until radiusd writes
#  a line, the command does not poll.  If radiusd writes neither message, the
#  `-e 30` option ends radiusd after 30 seconds.
#
#  Because the test needs Python only to send the Access-Request, the test is
#  in `TLS_PYTHON_TESTS` in `src/tests/tls/all.mk`.
#
#  Environment:
#    PYTHON         the Python interpreter
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    RADIUSD        command which runs radiusd, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding `dtls.conf`, `rlm_radius_tls_dynamic.conf`,
#                   and `rlm_radius_dtls_dynamic.py`
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      directory holding the dictionaries
#    PORT           TCP port unit_test_tls listens on, and the radius module
#                   connects to
#    LPORT          UDP port where radiusd listens.  The number is the same as
#                   PORT, because UDP and TCP ports are separate.
#
#  `make test.tls` sets every variable above and runs
#  `rlm_radius_tls_dynamic.sh`.  The recipe that does so is in
#  `src/tests/tls/all.mk`.
#
#  $Id$
#

LOG="$OUTPUT/rlm_radius_tls_dynamic_server.log"
RADIUSD_LOG="$OUTPUT/rlm_radius_tls_dynamic_radiusd.log"
RECEIPT="$OUTPUT/rlm_radius_tls_dynamic.receipt"
SERVER_RECEIPT="$OUTPUT/rlm_radius_tls_dynamic_server.receipt"
FIFO="$OUTPUT/rlm_radius_tls_dynamic.fifo"
HELPER="$OUTPUT/rlm_radius_tls_dynamic_radiusd.sh"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RADIUSD_LOG" "$RECEIPT" "$SERVER_RECEIPT" "$FIFO" "$HELPER"

fail() {
	echo "rlm_radius_tls_dynamic.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $RADIUSD_LOG ---"
	cat "$RADIUSD_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "rlm_radius_tls_dynamic.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

#
#  The command which unit_test_tls runs.  The script writes the command to a
#  file, so that quoting does not have to survive both `-e` and `sh -c`.
#
#  radiusd writes to the named pipe, and the loop below reads the pipe.  The
#  loop keeps reading after it stops radiusd, so that the log holds the
#  output of the shutdown.  The read ends when radiusd closes the pipe, which
#  is also what happens when radiusd fails to start.
#
cat > "$HELPER" <<'EOF'
mkfifo "$FIFO"

$RADIUSD -d "$CONFDIR" -D "$DICT_PATH" -n rlm_radius_tls_dynamic -msxx -e 30 -l stdout > "$FIFO" 2>&1 &
pid=$!
sender=

while IFS= read -r line; do
	printf '%s\n' "$line" >> "$RADIUSD_LOG"

	case "$line" in
	*"Ready to process requests"*)
		"$PYTHON" -I "$CONFDIR/rlm_radius_dtls_dynamic.py" >> "$RADIUSD_LOG.sender" 2>&1 &
		sender=$!
		;;
	*"TLS connection open"*|*"TLS connection failed"*)
		kill "$pid" 2> /dev/null
		;;
	esac
done < "$FIFO"

wait "$pid" 2> /dev/null
[ -z "$sender" ] || wait "$sender" 2> /dev/null
exit 0
EOF

export OUTPUT FIFO RADIUSD RADIUSD_LOG CONFDIR DICT_PATH PORT LPORT PYTHON
LISTENER=udp
export LISTENER

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx -r "$SERVER_RECEIPT" \
	-e 'sh "$OUTPUT/rlm_radius_tls_dynamic_radiusd.sh"' \
	> "$LOG" 2>&1

if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$LOG" "$RADIUSD_LOG"; then
	fail "a signal or a failed assertion appears in a log file"
fi

######################################################################
#
#  What the radius module did.
#
######################################################################
grep -q "TLS connection open" "$RADIUSD_LOG" || \
	fail "the radius module did not open the TLS connection"

#
#  unit_test_tls closes the connection after the handshake, and does not read
#  the Access-Request that the radius module sends once the connection is
#  open.  The radius module can therefore log a failed connection after the
#  connection opened.  Only a failure before the connection opened is an
#  error.
#
open_line=$(grep -n "TLS connection open" "$RADIUSD_LOG" | head -n 1 | cut -d: -f1)
failed_line=$(grep -n "TLS connection failed" "$RADIUSD_LOG" | head -n 1 | cut -d: -f1)

if [ -n "$failed_line" ] && [ "$failed_line" -lt "$open_line" ]; then
	fail "the radius module reported a failed TLS connection before the connection opened"
fi

######################################################################
#
#  What the home server did.
#
######################################################################
[ -e "$SERVER_RECEIPT" ] || fail "unit_test_tls did not create $SERVER_RECEIPT"

count=$(grep -c "connection state is now connected" "$LOG")
[ "$count" = "1" ] || fail "expected one connected state, found $count"

touch "$RECEIPT"
exit 0
