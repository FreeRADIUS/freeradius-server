#!/bin/sh
#
#  Start radiusd with threads, and the detail module writing to a
#  directory which can't be created.  Then send concurrent
#  Accounting-Requests for DURATION seconds, and check that the server
#  is still running, has replied to every request, and hasn't reported
#  corrupted memory.
#
#  usage: run.sh RADIUSD RADCLIENT CONFDIR DICTDIR OUTDIR PORT DURATION
#
#  RADIUSD and RADCLIENT may start with environment settings, as
#  $(TESTBIN) does.
#
RADIUSD=$1
RADCLIENT=$2
CONFDIR=$3
DICTDIR=$4
OUT=$5
PORT=$6
DURATION=$7

#
#  Each round runs CLIENTS radclients at once, each sending REQUESTS
#  requests, PARALLEL at a time.
#
CLIENTS=4
REQUESTS=200
PARALLEL=16

mkdir -p "$OUT"
PIDFILE="$OUT/radiusd.pid"
CORRUPT='CONSISTENCY\|talloc abort\|Bad talloc\|ERROR: AddressSanitizer'

#
#  Stop the server, and wait for it to exit, so that the port is free
#  for the next run.  Returns non-zero if it had to be killed.
#
stop() {
	[ -f "$PIDFILE" ] || return 0
	pid=$(cat "$PIDFILE")
	rm -f "$PIDFILE"
	kill "$pid" 2>/dev/null
	i=0
	while kill -0 "$pid" 2>/dev/null && [ $i -lt 100 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	kill -0 "$pid" 2>/dev/null || return 0
	kill -9 "$pid" 2>/dev/null
	return 1
}

#
#  Stop the radclients.  $(TESTBIN) may run each one under wrappers,
#  so stop every process under each one we started.
#
kill_tree() {
	for child in $(pgrep -P "$1"); do
		kill_tree "$child"
	done
	kill "$1" 2>/dev/null
}

clients=""
stop_clients() {
	for client in $clients; do
		kill_tree "$client"
	done
}

#
#  A server left behind by an interrupted run would hold the port.
#
stop
trap stop EXIT
trap 'stop_clients; stop; exit 1' INT TERM

#
#  The detail file's directory is under a regular file, so creating
#  it fails with ENOTDIR, even for root.
#
rm -rf "$OUT/notadir" "$OUT"/radclient.* "$OUT"/radiusd.*
: > "$OUT/notadir"

#
#  Distinct requests, and the reply each one should get.
#
i=1
while [ $i -le $REQUESTS ]; do
	printf 'User-Name = "bob"\nAcct-Status-Type = Start\nAcct-Session-Id = "%08x"\nNAS-IP-Address = 127.0.0.1\nNAS-Port = %d\n\n' $i $i
	i=$((i + 1))
done > "$OUT/acct.txt"
i=1
while [ $i -le $REQUESTS ]; do
	printf 'Reply-Message == "detail failed"\n\n'
	i=$((i + 1))
done > "$OUT/reply.txt"

ARGS="-f -P -d $CONFDIR -D $DICTDIR -l $OUT/radiusd.log"
TOP_SRCDIR=. OUTPUT="$OUT" PORT="$PORT" env $RADIUSD $ARGS > "$OUT/radiusd.out" 2>&1 &

i=0
while ! grep -q 'Ready to process requests' "$OUT/radiusd.log" 2>/dev/null; do
	if [ $i -ge 100 ]; then
		echo "FAILED STARTING RADIUSD: $RADIUSD $ARGS"
		tail -n 50 "$OUT/radiusd.log" "$OUT/radiusd.out"
		exit 1
	fi
	sleep 0.1
	i=$((i + 1))
done
pid=$(cat "$PIDFILE")

#
#  Each radclient's summary must count every request as having a
#  reply which says that the detail module failed.  radclient exits
#  with success when the server has gone, so its exit status isn't
#  enough.
#
ok=yes
why=""
end=$(($(date +%s) + DURATION))
round=0
while [ $(date +%s) -lt $end ] && kill -0 "$pid" 2>/dev/null; do
	n=0
	clients=""
	while [ $n -lt $CLIENTS ]; do
		log="$OUT/radclient.$round.$n"
		env $RADCLIENT -s -r 3 -t 2 -p $PARALLEL -f "$OUT/acct.txt:$OUT/reply.txt" -D "$DICTDIR" \
			127.0.0.1:$PORT acct testing123 > "$log" 2>&1 &
		clients="$clients $!"
		n=$((n + 1))
	done
	wait $clients
	for log in "$OUT"/radclient.$round.*; do
		grep -q "Passed filter *: $REQUESTS\$" "$log" || ok=no
	done
	[ "$ok" = "yes" ] || break
	rm -f "$OUT"/radclient.$round.*
	round=$((round + 1))
done

if ! kill -0 "$pid" 2>/dev/null; then
	ok=no
	why="$why radiusd died;"
elif [ "$ok" != "yes" ]; then
	why="$why requests were not answered, or the detail module did not fail;"
fi
stop || { ok=no; why="$why radiusd did not exit when asked;"; }

if grep -q "$CORRUPT" "$OUT/radiusd.log" "$OUT/radiusd.out"; then
	ok=no
	why="$why radiusd reported corrupted memory;"
fi

if [ "$ok" != "yes" ]; then
	echo "FAILED after $round rounds:$why"
	grep -h -m 5 "$CORRUPT" "$OUT/radiusd.log" "$OUT/radiusd.out"
	tail -n 10 "$OUT"/radclient.$round.*
	echo "RADIUSD: $RADIUSD $ARGS"
	exit 1
fi

#
#  The log has an error for every request.
#
rm -f "$OUT/radiusd.log"
