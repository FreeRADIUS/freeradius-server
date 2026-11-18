#!/bin/sh
#
#  Check Application Layer Protocol Negotiation (ALPN): the TLS extension
#  which lets both ends agree on what the tunnel carries before any of it is
#  sent.  The client offers a list of protocol names, the server picks one,
#  and the server sends back the name it picked.
#
#  The library holds no protocol names.  An application declares a table of
#  protocols, and the library builds the wire list from the table.  The table
#  of unit_test_tls has radius/1.1 (sticky), radius/1.0 (implied), and
#  http/1.1.  "-L names" lists the entries to offer, in the order of
#  preference.  "-a" sets the raw fields of the configuration instead, the way
#  an application does when it does not use a table.  See src/lib/tls/alpn.c.
#
#  A table based list is used only with TLS 1.3 and DTLS 1.2.  alpn.conf has
#  TLS 1.3 on both ends, unit_test_tls.conf has TLS 1.2 on both ends, and
#  dtls.conf has DTLS 1.2 on both ends.
#
#  This script runs many cases, where every other script in this directory
#  runs one.  Each case needs its own pair of command lines, so one case per
#  script would mean many copies of the sixty lines of server and client
#  plumbing below for about ten lines of checks each.  The cases share one
#  port, so they share one script instead, and tls_pair() holds the plumbing
#  once.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding alpn.conf and unit_test_tls.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

RECEIPT="$OUTPUT/alpn.receipt"

mkdir -p "$OUTPUT"
rm -f "$OUTPUT"/alpn_*.log "$OUTPUT"/alpn_cfg_*.conf "$RECEIPT"

fail() {
	fail_message="$1"

	echo "alpn.sh: $fail_message"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

#
#  Run one server, which starts one client against itself with -e, and
#  returns once both have exited.
#
#    tls_pair <case> <config name> <server args> <client args>
#
#  Sets SERVER_LOG and CLIENT_LOG for the checks which follow the call.  The
#  exit status of either program says nothing useful here, because many of
#  the cases are meant to fail, so neither is checked.  What the two logs
#  hold is the whole of what this script tests.
#
tls_pair() {
	pair_name="$1"
	pair_conf="$2"
	pair_server_args="$3"
	pair_client_args="$4"

	SERVER_LOG="$OUTPUT/alpn_${pair_name}_server.log"
	CLIENT_LOG="$OUTPUT/alpn_${pair_name}_client.log"

	CLIENT_ARGS="$pair_client_args"
	CLIENT_CONF="$pair_conf"
	export CLIENT_LOG CLIENT_ARGS CLIENT_CONF

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$pair_conf" -xx \
		$pair_server_args \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$CLIENT_CONF" -xx \
			-s "127.0.0.1:$PORT" $CLIENT_ARGS > "$CLIENT_LOG" 2>&1' \
		> "$SERVER_LOG" 2>&1

	#
	#  An abort during the handshake looks like an ordinary failure to
	#  the checks below, because the connection dies either way.  Say so
	#  here instead, in every case, so the cause is not mistaken for the
	#  symptom.
	#
	for check_log in "$SERVER_LOG" "$CLIENT_LOG"; do
		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$check_log"; then
			fail "a signal or a failed assertion appears in $check_log"
		fi
	done
}

#
#  Both ends completed the handshake once.
#
expect_completed() {
	for completed_log in "$SERVER_LOG" "$CLIENT_LOG"; do
		completed_count=$(grep -c "TLS handshake completed" "$completed_log")
		[ "$completed_count" = "1" ] || \
			fail "expected one completed handshake in $completed_log, found $completed_count"
	done
}

#
#  The server did not complete the handshake.
#
expect_server_refused() {
	if grep -q "TLS handshake completed" "$SERVER_LOG"; then
		fail "the server completed the handshake, although the two ends could not agree"
	fi
}

#
#  The log has no "agreed on" line for the name, which is how a connection
#  which used historic RADIUS/TLS looks.
#
expect_no_agreement() {
	for agreed_log in "$SERVER_LOG" "$CLIENT_LOG"; do
		if grep -q 'ALPN - agreed on "radius/1.1"' "$agreed_log"; then
			fail "radius/1.1 was negotiated in $agreed_log, but historic RADIUS/TLS was expected"
		fi
	done
}

######################################################################
#
#  1.  Both ends offer the same two names, in opposite orders.
#
#  The two orders are what makes this worth checking.  The server offers
#  radius/1.1 first and the client offers radius/1.0 first, so the name they
#  settle on says whose order decided it.  SSL_select_next_proto() walks the
#  server's list and takes the first name the client also offered, so the
#  answer must be radius/1.1.  If the client's order ever started deciding,
#  the answer would be radius/1.0 and this check would say so.
#
######################################################################
tls_pair order alpn '-L radius/1.1,radius/1.0' '-L radius/1.0,radius/1.1'

grep -q 'ALPN - chose "radius/1.1"' "$SERVER_LOG" || \
	fail "the server did not choose radius/1.1, so its own order did not decide"

for order_log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - agreed on "radius/1.1"' "$order_log" || \
		fail "no agreement on radius/1.1 in $order_log"

	#
	#  The name has to arrive whole.  SSL_get0_alpn_selected() hands back
	#  the name on its own, with no leading length octet, so reading it as
	#  though it had one drops the first character and yields "adius/1.1".
	#  The exact string below is what catches that.
	#
	grep -q 'session-state.TLS-ALPN = "radius/1.1"' "$order_log" || \
		fail "ALPN did not reach the session-state list whole in $order_log"

	#
	#  The application reads the table id of the entry which was
	#  negotiated, and not the name.  radius/1.1 is the first entry of the
	#  table of unit_test_tls, so the id is 0.
	#
	grep -q 'ALPN - table id 1' "$order_log" || \
		fail "the table id of radius/1.1 did not reach the log in $order_log"
done

expect_completed

######################################################################
#
#  2.  The two lists have nothing in common.
#
#  The server's select callback is what notices, and it notices during the
#  handshake, so the peer gets a fatal alert rather than a connection which
#  completes and is then torn down.  Alert 120 is no_application_protocol.
#  RFC 9765 Section 3.3 says the message SHOULD name the peer, so the
#  message names the address of the client.
#
######################################################################
tls_pair mismatch alpn '-L radius/1.1' '-L http/1.1'

grep -q "ALPN - no protocol in common with the peer" "$SERVER_LOG" || \
	fail "the server did not report that the two lists have nothing in common, with the peer address"

grep -q "Sending client fatal TLS alert (120)" "$SERVER_LOG" || \
	fail "the server did not send alert 120, no_application_protocol"

expect_server_refused

######################################################################
#
#  3.  RFC 9765 Table 2, one case for each of the sixteen cells.
#
#  The rows are what the client offers, and the columns are what the server
#  offers.  "none" means that the end uses no ALPN.  "both" means radius/1.1
#  and radius/1.0, in that order.
#
#                 server:   none     1.0      both     1.1
#      client: none         TLS      TLS      TLS      Close-S
#              1.0          TLS      TLS      TLS      Alert
#              both         TLS      TLS      1.1      1.1
#              1.1          Close-C  Alert    1.1      1.1
#
#  The outcomes are:
#
#    TLS      historic RADIUS/TLS, so the handshake completes and nothing
#             negotiates radius/1.1.
#    1.1      RADIUS/1.1, so the handshake completes and both ends agree on
#             radius/1.1.
#    Alert    the server's select callback finds nothing in common, and sends
#             alert 120.
#    Close-S  the server requires ALPN, and the client sent none.  The server
#             refuses while it parses the ClientHello, because radius/1.1 has
#             no implied entry to fall back to.
#    Close-C  the client requires ALPN, and the server sent none.  The client
#             refuses after the handshake.
#
######################################################################
SERVER_none=""
SERVER_10="-L radius/1.0"
SERVER_both="-L radius/1.1,radius/1.0"
SERVER_11="-L radius/1.1"

CLIENT_none=""
CLIENT_10="-L radius/1.0"
CLIENT_both="-L radius/1.1,radius/1.0"
CLIENT_11="-L radius/1.1"

#
#  cell <client offer> <server offer> <outcome>
#
cell() {
	cell_client="$1"
	cell_server="$2"
	cell_outcome="$3"

	eval "cell_client_args=\$CLIENT_${cell_client}"
	eval "cell_server_args=\$SERVER_${cell_server}"

	tls_pair "cell_${cell_client}_${cell_server}" alpn "$cell_server_args" "$cell_client_args"

	case "$cell_outcome" in
	TLS)
		expect_completed
		expect_no_agreement
		;;

	1.1)
		expect_completed
		for cell_log in "$SERVER_LOG" "$CLIENT_LOG"; do
			grep -q 'ALPN - agreed on "radius/1.1"' "$cell_log" || \
				fail "client $cell_client and server $cell_server did not agree on radius/1.1 in $cell_log"
		done
		;;

	Alert)
		grep -q "ALPN - no protocol in common with the peer" "$SERVER_LOG" || \
			fail "client $cell_client and server $cell_server did not reach the select callback failure"
		grep -q "Sending client fatal TLS alert (120)" "$SERVER_LOG" || \
			fail "client $cell_client and server $cell_server did not send alert 120"
		expect_server_refused
		;;

	Close-S)
		grep -q "ALPN - Failure, client offered no ALPN and no default ALPN string was configured" "$SERVER_LOG" || \
			fail "client $cell_client and server $cell_server did not refuse in the ClientHello"
		grep -q "Sending client fatal TLS alert (120)" "$SERVER_LOG" || \
			fail "client $cell_client and server $cell_server did not send alert 120"
		expect_server_refused
		;;

	Close-C)
		grep -q "ALPN - Failure, no protocols in common" "$CLIENT_LOG" || \
			fail "client $cell_client and server $cell_server did not refuse after the handshake"
		if grep -q "TLS handshake completed" "$CLIENT_LOG"; then
			fail "the client completed the handshake, although the server sent no ALPN"
		fi
		;;
	esac
}

cell none none TLS
cell none 10 TLS
cell none both TLS
cell none 11 Close-S

cell 10 none TLS
cell 10 10 TLS
cell 10 both TLS
cell 10 11 Alert

cell both none TLS
cell both 10 TLS
cell both both 1.1
cell both 11 1.1

cell 11 none Close-C
cell 11 10 Alert
cell 11 both 1.1
cell 11 11 1.1

######################################################################
#
#  4.  A table based list is not used with TLS 1.2 or earlier.
#
#  RFC 9765 Section 3.4 says implementations MUST require TLS 1.3, and OpenSSL
#  has no DTLS 1.3, so the library also allows DTLS 1.2.  unit_test_tls.conf
#  limits both ends to TLS 1.2.  OpenSSL has not chosen the TLS version when the
#  select callback runs, so the ClientHello callback works out whether TLS 1.3
#  will be negotiated, and the select callback then chooses no name.
#
#  With radius/1.0 in the list, the two ends fall back to it, which is
#  historic RADIUS/TLS.  Without radius/1.0, nothing is implied, so the server
#  refuses while it parses the ClientHello.
#
######################################################################
tls_pair tls12_implied unit_test_tls '-L radius/1.1,radius/1.0' '-L radius/1.1,radius/1.0'

grep -q "ALPN - not used with TLS 1.2 or earlier, choosing no name" "$SERVER_LOG" || \
	fail "the server did not skip ALPN below TLS 1.3"

for tls12_log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - peer used no ALPN, assuming "radius/1.0"' "$tls12_log" || \
		fail "the peer was not assumed to speak radius/1.0 in $tls12_log"
done

expect_completed
expect_no_agreement

tls_pair tls12_required unit_test_tls '-L radius/1.1' '-L radius/1.1,radius/1.0'

grep -q "ALPN - Failure, TLS 1.2 or earlier will be negotiated and no default ALPN string was configured" "$SERVER_LOG" || \
	fail "the server did not refuse radius/1.1 below TLS 1.3"

expect_server_refused

#
#  OpenSSL has no DTLS 1.3, so a table based list is used with DTLS 1.2 as
#  well as with TLS 1.3.  dtls.conf has the DTLS 1.2 transport on both ends.
#  The cases below are the cells of RFC 9765 Table 2 which show the outcomes
#  that differ in kind: RADIUS/1.1, historic RADIUS/TLS, an alert, Close-S, and
#  Close-C.
#
tls_pair dtls_both dtls '-L radius/1.1,radius/1.0' '-L radius/1.1,radius/1.0'

for dtls_log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - agreed on "radius/1.1"' "$dtls_log" || \
		fail "no agreement on radius/1.1 over DTLS in $dtls_log"
done

expect_completed

tls_pair dtls_implied dtls '-L radius/1.1,radius/1.0' ''

grep -q 'ALPN - peer used no ALPN, assuming "radius/1.0"' "$SERVER_LOG" || \
	fail "the peer was not assumed to speak radius/1.0 over DTLS"

expect_completed
expect_no_agreement

tls_pair dtls_alert dtls '-L radius/1.1' '-L radius/1.0'

grep -q "ALPN - no protocol in common with the peer" "$SERVER_LOG" || \
	fail "the server did not find that the two lists have nothing in common over DTLS"

expect_server_refused

tls_pair dtls_close_s dtls '-L radius/1.1' ''

grep -q "ALPN - Failure, client offered no ALPN and no default ALPN string was configured" "$SERVER_LOG" || \
	fail "the server did not refuse a DTLS client which offered no ALPN"

expect_server_refused

tls_pair dtls_close_c dtls '' '-L radius/1.1'

grep -q "ALPN - Failure, no protocols in common" "$CLIENT_LOG" || \
	fail "the DTLS client did not refuse a server which sent no ALPN"

######################################################################
#
#  5.  The server requires an agreement, and the client offers no list,
#      with the raw fields.
#
#  A list that the application sets itself is checked only after the
#  handshake, by fr_tls_session_alpn_check().  The ClientHello callback and
#  the select callback skip a list which has no table.
#
#  This is also the case which says `alpn_required` is not merely advisory:
#  without it the same pair of command lines completes, which is what case 4
#  of alert_recv.sh would look like if ALPN were optional here.
#
######################################################################
tls_pair raw_required alpn '-a -L radius/1.1 -l' ''

grep -q "ALPN - Failure, no protocols in common" "$SERVER_LOG" || \
	fail "the server did not refuse a session which agreed on no protocol"

grep -q "request.Error = ::ALPN-Failed" "$SERVER_LOG" || \
	fail "the refusal did not record ALPN-Failed"

expect_server_refused

tls_pair raw_both alpn '-a -L radius/1.1,radius/1.0' '-a -L radius/1.0,radius/1.1'

for raw_log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - agreed on "radius/1.1"' "$raw_log" || \
		fail "the raw fields did not agree on radius/1.1 in $raw_log"
done

expect_completed

######################################################################
#
#  6.  An agreement is required, and no names were given to agree on.
#
#  Requiring an agreement while offering nothing to agree on fails every
#  session.  fr_tls_ctx_alpn_set() says so once, at startup, rather than
#  letting every session fail for a reason the log does not explain.  No
#  client is needed, because the server never listens.
#
######################################################################
SERVER_LOG="$OUTPUT/alpn_unusable_server.log"
CLIENT_LOG="$SERVER_LOG"

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n alpn -xx -l \
	> "$SERVER_LOG" 2>&1

grep -q "ALPN is required, but no protocols were set" "$SERVER_LOG" || \
	fail "a required agreement with no names did not fail at startup"

if grep -q "Waiting for a connection" "$SERVER_LOG"; then
	fail "the server listened, although its ALPN configuration cannot work"
fi

######################################################################
#
#  7.  The `alpn` section of the configuration file.
#
#  fr_tls_alpn_parse() reads the section.  Each item is the configuration
#  name of a table entry, and the order of the items is the order of
#  preference.  A missing section means no ALPN, which RFC 9765 Section 3.3
#  calls "unset".
#
#  Each variant of alpn.conf below is alpn.conf with an `alpn` section added
#  to the server.  The variants are written into $OUTPUT, so the $INCLUDE line
#  names the path of common.conf.
#
######################################################################

#
#  cfg_write <variant> <items>
#
#  Writes $OUTPUT/alpn_cfg_<variant>.conf.  The items replace the marker line
#  which follows `virtual_server = tls` in the server section.
#
cfg_write() {
	cfg_variant="$1"
	cfg_items="$2"

	sed -e "s|^\\\$INCLUDE common.conf|\$INCLUDE $CONFDIR/common.conf|" \
	    -e "s|^\\(\\t*\\)virtual_server = tls\$|&\\
\\1alpn {\\
\\1$cfg_items\\
\\1}|" \
	    "$CONFDIR/alpn.conf" > "$OUTPUT/alpn_cfg_${cfg_variant}.conf"
}

#
#  cfg_pair <variant> <client args>
#
#  Like tls_pair(), with the variant as the configuration of both ends, and
#  the server taking its list from the file.
#
cfg_pair() {
	cfg_pair_variant="$1"
	cfg_pair_client_args="$2"

	CONFDIR_SAVED="$CONFDIR"
	CONFDIR="$OUTPUT"
	tls_pair "cfg_${cfg_pair_variant}" "alpn_cfg_${cfg_pair_variant}" "" "$cfg_pair_client_args"
	CONFDIR="$CONFDIR_SAVED"
}

#
#  Only radius/1.1 is enabled, so a client offering both names settles on
#  radius/1.1, and a client which offers nothing is refused because nothing is
#  implied.
#
cfg_write only11 "radius_v1_1 = yes\\
\\1radius_v1_0 = no"

cfg_pair only11 '-L radius/1.0,radius/1.1'

for cfg_log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - agreed on "radius/1.1"' "$cfg_log" || \
		fail "the alpn section did not agree on radius/1.1 in $cfg_log"
done

cfg_pair only11 ''

grep -q "ALPN - Failure, client offered no ALPN and no default ALPN string was configured" "$SERVER_LOG" || \
	fail "the alpn section did not refuse a client which offered no ALPN"

#
#  Both names are enabled, and radius/1.0 is first, so the order of the items
#  is the order of preference and the server chooses radius/1.0.
#
cfg_write ordered "radius_v1_0 = yes\\
\\1radius_v1_1 = yes"

cfg_pair ordered '-L radius/1.1,radius/1.0'

grep -q 'ALPN - chose "radius/1.0"' "$SERVER_LOG" || \
	fail "the order of the items in the alpn section did not decide the choice"

expect_completed

#
#  cfg_bad <variant> <items> <message>
#
#  A bad section stops the program at startup, before the program listens.
#
cfg_bad() {
	bad_variant="$1"
	bad_items="$2"
	bad_message="$3"

	cfg_write "$bad_variant" "$bad_items"

	SERVER_LOG="$OUTPUT/alpn_cfg_${bad_variant}_server.log"
	CLIENT_LOG="$SERVER_LOG"

	$UNIT_TEST_TLS -d "$OUTPUT" -D "$DICT_PATH" -n "alpn_cfg_${bad_variant}" -xx \
		> "$SERVER_LOG" 2>&1

	grep -q "$bad_message" "$SERVER_LOG" || \
		fail "the alpn section '$bad_variant' did not report: $bad_message"

	if grep -q "Waiting for a connection" "$SERVER_LOG"; then
		fail "the server listened, although the alpn section '$bad_variant' is invalid"
	fi
}

cfg_bad empty "" "The .alpn. section is empty"
cfg_bad unknown "radius_v2_0 = yes" "Unknown ALPN item 'radius_v2_0'"
cfg_bad duplicate "radius_v1_1 = yes\\
\\1radius_v1_1 = no" "Duplicate ALPN item 'radius_v1_1'"
cfg_bad value "radius_v1_1 = maybe" "Invalid value for ALPN item 'radius_v1_1'"
cfg_bad none "radius_v1_1 = no\\
\\1radius_v1_0 = no" "does not enable any protocol"

touch "$RECEIPT"
exit 0
