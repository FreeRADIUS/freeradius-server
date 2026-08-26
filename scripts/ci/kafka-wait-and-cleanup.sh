#!/bin/sh
#
#  Block until kafka-subscribe.sh has written COUNT records to
#  OUT_FILE, then emit the accumulated records as a single JSON array
#  on stdout.
#
#  ---------------------------------------------------------------------
#  Why the named pipe, instead of the much shorter:
#
#      tail -f "$OUT" | while read _; do ... done
#
#  On BSD (macOS, FreeBSD), `tail -f` blocks inside a `kevent()` call
#  on a kqueue registered for file-change notifications on OUT.  It
#  only wakes up when OUT is written to - *not* when the pipe
#  downstream is closed.  So the sequence:
#
#      1. our `read` loop exits after the Nth line
#      2. the subshell exits, closing the pipe's read end
#      3. `tail` is still parked in `kevent()` waiting for the next
#         file write - it never attempts a write, so the kernel never
#         delivers SIGPIPE to it
#      4. the outer shell waits for the pipeline to finish before
#         moving on, and waits forever for `tail`
#
#  SIGPIPE only arrives when a process *writes* to a pipe whose read
#  end has been closed.  `tail` isn't writing while it's parked on
#  kqueue, so it never notices.  There's no portable way to push
#  `tail` out of that `kevent()` from within the pipeline.
#
#  The named pipe fixes this by letting us hold `tail`'s PID.  We
#  background `tail` with its stdout redirected into the FIFO, read
#  from the FIFO ourselves, and once we've counted COUNT records we
#  send `tail` an explicit SIGTERM - which *does* interrupt `kevent()`
#  on both kqueue and epoll platforms - and wait for it to reap.
#  ---------------------------------------------------------------------
#
#  Stdout is a JSON array suitable for `map json` inside the test:
#
#      map json %exec('...kafka-wait-and-cleanup.sh...', 'OUT', 'N') {
#          control.Tmp-String-0 := '$[0].value'
#          ...
#      }
#
#  The caller wraps the invocation in an unlang `timeout Ns { }` block -
#  that's the sole upper bound on how long the test is willing to wait
#  for the subscriber to catch up.
#
#  Usage:
#    kafka-wait-and-cleanup OUTPUT_FILE COUNT

set -eu

OUT=${1:?"output file required"}
WANT=${2:?"count required"}

FIFO=$(mktemp -u)
mkfifo -m 0600 "$FIFO"

#
#  On exit (clean or via timeout from the caller), reap the subscriber
#  that kafka-subscribe.sh forked.  In the happy path `rpk -n COUNT`
#  has already exited on its own; this catches the short-read case
#  where the test got fewer records than requested and we'd otherwise
#  leak the `docker exec` until the next topic reset.
#
cleanup() {
	if [ -f "$OUT.pid" ]; then
		sub_pid=$(cat "$OUT.pid" 2>/dev/null || true)
		if [ -n "${sub_pid:-}" ]; then
			kill "$sub_pid" 2>/dev/null || true
		fi
		rm -f -- "$OUT.pid"
	fi
	rm -f -- "$FIFO"
}
trap cleanup EXIT

tail -f "$OUT" 2>/dev/null >"$FIFO" &
TAIL_PID=$!

#
#  Keep the FIFO open on fd 3 so each `read` doesn't reopen and race
#  with `tail` attaching.
#
exec 3<"$FIFO"
n=0
while [ "$n" -lt "$WANT" ]; do
	IFS= read -r _ <&3 || break
	n=$((n + 1))
done
exec 3<&-

#
#  `tail` is still blocked on kqueue waiting for more data; kill it.
#
kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true

printf '['
paste -sd, -- "$OUT"
printf ']\n'
