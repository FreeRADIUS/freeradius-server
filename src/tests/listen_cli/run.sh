#!/bin/sh
#
#  Start radiusd with "-i 127.0.0.1 -p PORT", and "-n NAME" if NAME is
#  given.  Then check that the authentication listener on PORT and the
#  accounting listener on PORT + 1 both answer from the expected
#  virtual server.
#
#  usage: run.sh RADIUSD RADCLIENT CONFDIR DICTDIR OUTDIR PORT SERVER [NAME]
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
SERVER=$7
NAME=$8

mkdir -p "$OUT"
PIDFILE="$OUT/radiusd.pid"

#
#  Stop the server, and wait for it to exit, so that the ports are
#  free for the next run.
#
stop() {
	[ -f "$PIDFILE" ] || return 0
	pid=$(cat "$PIDFILE")
	kill "$pid" 2>/dev/null
	i=0
	while kill -0 "$pid" 2>/dev/null && [ $i -lt 50 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	kill -9 "$pid" 2>/dev/null
	rm -f "$PIDFILE"
}

#
#  A server left behind by an interrupted run would hold the ports.
#
stop
trap stop EXIT INT TERM

ARGS="-Pxxx -d $CONFDIR -D $DICTDIR -l $OUT/radiusd.log -i 127.0.0.1 -p $PORT"
[ -n "$NAME" ] && ARGS="$ARGS -n $NAME"

if ! TOP_SRCDIR=. OUTPUT="$OUT" env $RADIUSD $ARGS; then
	echo "FAILED STARTING RADIUSD: $RADIUSD $ARGS"
	tail -n 50 "$OUT/radiusd.log"
	exit 1
fi

#
#  Each virtual server puts its name in the Reply-Message.
#
printf 'Reply-Message == "%s"\nMessage-Authenticator =* ANY\n' "$SERVER" > "$OUT/auth-reply.txt"
printf 'Reply-Message == "%s"\n' "$SERVER" > "$OUT/acct-reply.txt"

ok=yes
env $RADCLIENT -r 1 -t 2 -f "$CONFDIR/../auth.txt:$OUT/auth-reply.txt" -D "$DICTDIR" 127.0.0.1:$PORT auth testing123 > "$OUT/radclient.log" 2>&1 || ok=no
env $RADCLIENT -r 1 -t 2 -f "$CONFDIR/../acct.txt:$OUT/acct-reply.txt" -D "$DICTDIR" 127.0.0.1:$((PORT + 1)) acct testing123 >> "$OUT/radclient.log" 2>&1 || ok=no

for type in auth acct; do
	grep -q "Listening on $type address 127.0.0.1 port .* bound to server $SERVER\$" "$OUT/radiusd.log" || ok=no
done

if [ "$ok" != "yes" ]; then
	cat "$OUT/radclient.log"
	grep 'Listening on' "$OUT/radiusd.log"
	echo "RADIUSD: $RADIUSD $ARGS"
	exit 1
fi
