#!/bin/sh
#
#  Start radiusd, leave an Access-Challenge unanswered so that its
#  session-state is still saved, then stop the server.  The server
#  must free that session-state as it exits: a build with the leak
#  sanitizer reports anything it doesn't free, and exits with an
#  error.
#
#  usage: run.sh RADIUSD RADCLIENT CONFDIR DICTDIR OUTDIR PORT
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

mkdir -p "$OUT"
PIDFILE="$OUT/radiusd.pid"
LOG="$OUT/radiusd.log"

#
#  A server left behind by an interrupted run would hold the port.
#
if [ -f "$PIDFILE" ]; then
	kill -9 "$(cat "$PIDFILE")" 2>/dev/null
	rm -f "$PIDFILE"
fi
rm -f "$LOG"

#
#  Run the server in the foreground, as our child, so that we can
#  wait for it to exit, and see how it exited.  With "-x", it points
#  stderr at its log file, so the log gets what the sanitizers print
#  at exit.
#
ARGS="-f -Pxxx -d $CONFDIR -D $DICTDIR -l $LOG -i 127.0.0.1 -p $PORT"
TOP_SRCDIR=. OUTPUT="$OUT" env $RADIUSD $ARGS &
child=$!
trap 'kill -9 $child 2>/dev/null' EXIT INT TERM

i=0
while ! grep -q 'Ready to process requests' "$LOG" 2>/dev/null; do
	if ! kill -0 $child 2>/dev/null || [ $i -ge 100 ]; then
		echo "FAILED STARTING RADIUSD: $RADIUSD $ARGS"
		tail -n 50 "$LOG"
		exit 1
	fi
	sleep 0.1
	i=$((i + 1))
done

ok=yes
printf 'Packet-Type == Access-Challenge\n' > "$OUT/reply.txt"
env $RADCLIENT -r 1 -t 2 -f "$CONFDIR/../auth.txt:$OUT/reply.txt" -D "$DICTDIR" 127.0.0.1:$PORT auth testing123 > "$OUT/radclient.log" 2>&1 || ok=no

kill "$(cat "$PIDFILE")" 2>/dev/null || kill $child
wait $child
rcode=$?
trap - EXIT INT TERM
rm -f "$PIDFILE"

if [ "$ok" != "yes" ]; then
	cat "$OUT/radclient.log"
	echo "RADIUSD: $RADIUSD $ARGS"
	exit 1
fi

if [ $rcode -ne 0 ] || grep -q 'Sanitizer' "$LOG"; then
	echo "radiusd exited with status $rcode"
	sed -n '/Sanitizer/,$p' "$LOG"
	exit 1
fi
