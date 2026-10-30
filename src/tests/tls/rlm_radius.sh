#!/bin/sh
#
#  Check that the `radius` module can open a RADIUS/TLS connection to a home
#  server.
#
#  unit_test_tls is the home server.  unit_test_tls listens, accepts one
#  connection, runs the TLS handshake, and writes the receipt file when the
#  handshake succeeds.  unit_test_tls does not handle RADIUS packets, so this
#  test covers the connection and the handshake, and does not send a packet.
#
#  unit_test_tls runs radiusd as the command of `-e`, once unit_test_tls is
#  listening.  radiusd.conf in this directory configures the `radius` module
#  with a `tls` section.  The `radius` module starts one connection when the
#  server starts, so radiusd connects without a packet.
#
#  The unit_test_tls run and the unit_test_bio run of this test can run at
#  the same time, and both use radiusd.conf.  `radiusd -m` allows two
#  radiusd processes to read the same configuration file.
#
#  unit_test_tls accepts one connection, and the `radius` module opens one
#  connection for each thread.  `radiusd -s` runs radiusd with one thread, so
#  the one connection is the one that unit_test_tls accepts.
#
#  unit_test_tls waits for the command to exit, and radiusd does not exit by
#  itself.  The command therefore reads the output of radiusd through a named
#  pipe, and stops radiusd when the output says that the TLS connection is
#  open or that the TLS connection failed.  The read blocks until radiusd
#  writes a line, so the command does not poll.  `radiusd -e` is the limit
#  for a radiusd which writes neither message.
#
#  The server certificate must be accepted by the `radius` module, and the
#  client certificate must be accepted by unit_test_tls.  The configuration
#  of unit_test_tls sets `require_client_certificate`, so a connection which
#  does not present the client certificate does not complete.
#
#  Environment:
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    RADIUSD        command which runs radiusd, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf and radiusd.conf
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on, and radiusd connects to
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

LOG="$OUTPUT/rlm_radius_server.log"
RADIUSD_LOG="$OUTPUT/rlm_radius_radiusd.log"
RECEIPT="$OUTPUT/rlm_radius.receipt"
SERVER_RECEIPT="$OUTPUT/rlm_radius_server.receipt"
FIFO="$OUTPUT/rlm_radius.fifo"
HELPER="$OUTPUT/rlm_radius_radiusd.sh"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RADIUSD_LOG" "$RECEIPT" "$SERVER_RECEIPT" "$FIFO" "$HELPER"

fail() {
	echo "rlm_radius.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $RADIUSD_LOG ---"
	cat "$RADIUSD_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "rlm_radius.sh: no client certificate in $CERTDIR, run 'make certs'"
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

$RADIUSD -d "$CONFDIR" -D "$DICT_PATH" -msxx -e 30 -l stdout > "$FIFO" 2>&1 &
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

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx -r "$SERVER_RECEIPT" \
	-e 'sh "$OUTPUT/rlm_radius_radiusd.sh"' \
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
