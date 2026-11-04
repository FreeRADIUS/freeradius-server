#!/bin/sh
#
#  Check that the `radius` module can open a Datagram Transport Layer Security
#  (DTLS) connection to a home server, as RADIUS/DTLS.
#
#  unit_test_tls is the home server.  `dtls.conf` makes unit_test_tls listen
#  on a UDP socket.  unit_test_tls waits for a client, runs the DTLS handshake,
#  and writes the server receipt file (`rlm_radius_dtls_server.receipt` in
#  `$OUTPUT`) when the handshake succeeds.  Because unit_test_tls does not
#  handle RADIUS packets, this test covers the connection and the handshake,
#  and does not send a packet.
#
#  unit_test_tls runs the command that the `-e` option gives, once
#  unit_test_tls is listening.  The command runs radiusd with
#  `rlm_radius_dtls.conf`, which configures the `radius` module with a `tls`
#  subsection inside of the `udp` subsection.  Because the `radius` module
#  starts one connection when the server starts, radiusd connects before any
#  packet arrives.
#
#  The unit_test_tls run and the unit_test_bio run of this test can run at
#  the same time, and both use `rlm_radius_dtls.conf`.  `radiusd -m` allows
#  two radiusd processes to read the same configuration file.
#
#  unit_test_tls accepts one connection, and the `radius` module opens one
#  connection for each thread.  Because `radiusd -s` runs radiusd with one
#  thread, radiusd opens only the connection that unit_test_tls accepts.
#
#  unit_test_tls waits for the command to exit.  Because radiusd does not exit
#  by itself, the command reads the output of radiusd through a named pipe,
#  and stops radiusd when the output says that the TLS connection is open or
#  that the TLS connection failed.  Because the read blocks until radiusd
#  writes a line, the command does not poll.  If radiusd writes neither
#  message, `radiusd -e 30` ends radiusd after 30 seconds.
#
#  The `radius` module must accept the server certificate, and unit_test_tls
#  must accept the client certificate.  Because the configuration of
#  unit_test_tls sets `require_client_certificate`, a connection that does not
#  present the client certificate does not complete.
#
#  Environment:
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    RADIUSD        command which runs radiusd, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding dtls.conf and rlm_radius_dtls.conf
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on, and radiusd connects to
#
#  `make test.tls` sets every variable above and runs this script.  The recipe
#  is in `src/tests/tls/all.mk`.
#
#  $Id$
#

LOG="$OUTPUT/rlm_radius_dtls_server.log"
RADIUSD_LOG="$OUTPUT/rlm_radius_dtls_radiusd.log"
RECEIPT="$OUTPUT/rlm_radius_dtls.receipt"
SERVER_RECEIPT="$OUTPUT/rlm_radius_dtls_server.receipt"
FIFO="$OUTPUT/rlm_radius_dtls.fifo"
HELPER="$OUTPUT/rlm_radius_dtls_radiusd.sh"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RADIUSD_LOG" "$RECEIPT" "$SERVER_RECEIPT" "$FIFO" "$HELPER"

fail() {
	echo "rlm_radius_dtls.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $RADIUSD_LOG ---"
	cat "$RADIUSD_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "rlm_radius_dtls.sh: no client certificate in $CERTDIR, run 'make certs'"
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

$RADIUSD -d "$CONFDIR" -D "$DICT_PATH" -n rlm_radius_dtls -msxx -e 30 -l stdout > "$FIFO" 2>&1 &
pid=$!

while IFS= read -r line; do
	printf '%s\n' "$line" >> "$RADIUSD_LOG"

	case "$line" in
	*"TLS connection open"*|*"TLS connection failed"*)
		kill "$pid" 2> /dev/null
		;;
	esac
done < "$FIFO"

wait "$pid" 2> /dev/null
exit 0
EOF

export OUTPUT FIFO RADIUSD RADIUSD_LOG CONFDIR DICT_PATH PORT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx -r "$SERVER_RECEIPT" \
	-e 'sh "$OUTPUT/rlm_radius_dtls_radiusd.sh"' \
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

if grep -q "TLS connection failed" "$RADIUSD_LOG"; then
	fail "the radius module reported a failed TLS connection"
fi

#
#  The module sends a close_notify before it closes the socket, which
#  requires the TLS bio to write before the FD bio closes.
#
grep -q "Sending close_notify" "$RADIUSD_LOG" || \
	fail "the radius module did not send a close_notify when radiusd stopped"

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
