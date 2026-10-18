#!/bin/sh
#
#  Check delayed session tickets.
#
#  EAP sets `delayed_tickets` on every TLS configuration it uses, so that the
#  ticket can be sent after the inner authentication has succeeded.  -T sets
#  the same flag on the server here.  For a TLS 1.3 server with stateless
#  tickets, OpenSSL then sends no ticket in the handshake.  The connection
#  code calls fr_tls_ticket_issue() once the handshake is done, which runs
#  `encode session`, puts the session-state list into the session, and asks
#  OpenSSL for a ticket.
#
#  Each case makes two connections.  The second connection has to resume from
#  the ticket from the first connection, and that shows that OpenSSL kept the
#  ticket application data, which is the session-state list.  The `encode
#  session` section in common.conf sets a value in the list, and the `decode
#  session` section refuses a resumption which does not get the value back.
#  A ticket which lost the list would make the second connection a full
#  handshake, and the check for one resumed session would fail.
#
#  Four cases, one server run each:
#
#    tls13_default  TLS 1.3, no -T.  The ticket is made in the handshake.
#    tls13_delayed  TLS 1.3, -T.  The ticket is made after the handshake.
#                   Every `encode session` has to be logged after the
#                   handshake finished.
#    tls12_stateless TLS 1.2, with and without -T.  Stateless tickets are not
#    tls12_delayed   used below TLS 1.3, so no ticket is made and no section
#                    runs.  Both connections are full handshakes.
#
#  Each connection has to finish.  The server sends one byte of application
#  data (-P), which tells the client that no ticket is still coming.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding stateless.conf and delayed_tickets_12.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.
#
#  $Id$
#

RECEIPT="$OUTPUT/delayed_tickets.receipt"

mkdir -p "$OUTPUT"
rm -f "$RECEIPT"

fail() {
	echo "$1"
	for f in "$OUTPUT"/delayed_tickets_*.log; do
		[ -e "$f" ] || continue
		echo "--- $f ---"
		cat "$f"
	done
	exit 1
}

#
#  run <case> <config name> <expected version> <delayed> <encode session count> <resumed> [server options]
#
run() {
	name="$1"
	conf="$2"
	version="$3"
	delayed="$4"
	encodes="$5"
	resumed="$6"
	shift 6

	server_log="$OUTPUT/delayed_tickets_${name}_server.log"
	client_log="$OUTPUT/delayed_tickets_${name}_client.log"
	server_receipt="$OUTPUT/delayed_tickets_${name}_server.receipt"
	client_receipt="$OUTPUT/delayed_tickets_${name}_client.receipt"

	rm -f "$server_log" "$client_log" "$server_receipt" "$client_receipt"

	export client_log client_receipt conf

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 -P "$@" \
		-r "$server_receipt" \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 \
			-s "127.0.0.1:$PORT" -r "$client_receipt" > "$client_log" 2>&1' \
		> "$server_log" 2>&1

	[ -e "$server_receipt" ] || fail "$name: server did not create $server_receipt"
	[ -e "$client_receipt" ] || fail "$name: client did not create $client_receipt"

	for log in "$server_log" "$client_log"; do
		count=$(grep -c "TLS handshake completed" "$log")
		[ "$count" = "2" ] || fail "$name: expected two completed handshakes in $log, found $count"

		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
			fail "$name: a signal or a failed assertion appears in $log"
		fi
	done

	grep -q "version    : $version" "$server_log" || \
		fail "$name: the server did not negotiate $version"

	for log in "$server_log" "$client_log"; do
		count=$(grep -c "resumed    : yes" "$log")
		[ "$count" = "$resumed" ] || fail "$name: expected $resumed resumed sessions in $log, found $count"
	done

	count=$(grep -c "# encode session" "$server_log")
	[ "$count" = "$encodes" ] || fail "$name: expected $encodes encode session on the server, found $count"

	count=$(grep -c "# decode session" "$server_log")
	[ "$count" = "$resumed" ] || fail "$name: expected $resumed decode session on the server, found $count"

	#
	#  With delayed tickets, no `encode session` runs until the handshake has
	#  finished.  The first one has to be logged after the first
	#  "TLS handshake completed".
	#
	if [ "$delayed" = "1" ]; then
		done_line=$(grep -n "TLS handshake completed" "$server_log" | head -1 | cut -d: -f1)
		encode_line=$(grep -n "# encode session" "$server_log" | head -1 | cut -d: -f1)
		[ "$encode_line" -gt "$done_line" ] || \
			fail "$name: encode session ran at line $encode_line, before the handshake finished at line $done_line"
	fi

	#
	#  The server keeps nothing, so neither cache section runs there.
	#
	for section in "load session" "store session"; do
		if grep -q "# $section" "$server_log"; then
			fail "$name: '$section' ran on the server, with stateless tickets"
		fi
	done
}

#
#  TLS 1.3 issues a new ticket for each connection, resumed or not.  TLS 1.2
#  gets no stateless ticket at all, so nothing runs `encode session` or
#  `decode session`, and the second connection is a full handshake.
#
run tls13_default stateless TLSv1.3 0 2 1
run tls13_delayed stateless TLSv1.3 1 2 1 -T
run tls12_stateless delayed_tickets_12 TLSv1.2 0 0 0
run tls12_delayed delayed_tickets_12 TLSv1.2 0 0 0 -T

touch "$RECEIPT"
