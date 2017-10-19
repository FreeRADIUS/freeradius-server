# Detail file reader

## What works

proto_detail and proto_detail_file can work together to read a
pre-existing `detail.work` file, process it to completion, and close
the file.

The detail listener can be configured to read Accounting-Request,
CoA-Request, or Disconnect-Request packets.

The detail file listener can programmattically set priorities for the
packets.

Event-Timestamp and Acct-Delay-Time are set for accounting packets.

Use `MPRINT` to debug the file reading.

Basic sanity checks of the file format is done.

Once a `read()` returns data AND at least one packet, the FD is paused
until all of the `write()` functions return.  This allows the detail
file reader to be "self clocked".  i.e. if the server isn't busy, the
file is read at 100% speed.  If the server is busy, the file is read
only when it becomes un-busy enough to respond to the packets.

The packets are processed through `recv {}` and `send {}` sections.
Note no second name!  That could be change?

The `send Do-Not-Respond { }` section should work.

The default packet size is 64K.  If detail file entries are larger
than this, you will have to set `max_packet_size` to something larger.
Otherwise, larger packets are skipped.

## What doesn't work

The `send Protocol-Error { }` section is there, but doesn't work.

The "self clocking" has some limitations.  Right now, it reads
`max_packet_size` data from the file, and adds *all* packets in the
file.  So it's somewhat bursty.  It would be nice to read one packet,
process it, and then read another only when the first one is done.

The issue with that is the event loop is FD based.  There's no way
right now to determine that the FD may not be ready, but there's still
more data in the `fr_network_socket_t` structure.  Fixing that
requires the network code to track sockets which have partial data,
but are paused.

The code hasn't been tested with very large detail files.

"too large" packets haven't been tested well.

The "Done" packets haven't been tested well.

The read_pause / read_continue hasn't been tested with large detail
files.

The polling for detail files hasn't been written.  No `glob()`, rename
"detail_foo` to `detail.work`, no locking of the detail file.

The VNODE work hasn't been started.  That's the code which will open a
EVFILT_VNODE with NOTE_EXTEND on the directory.  Then, once it gets a
signal, either open `detail.work`, or call `glob()` to find the oldest
detail file, rename it to `detail.work`, and process that.  With
locking, etc.

We still have to figure out how to open a locked file from
`proto_detail_file`, probably via having the parent open the file,
lock it, and (somehow) create the child, and pass the opened FD to the
child.

When the child is done, it should notify the parent VNODE handler that
the file is done, so that the parent can troll through the directory
again.  Or maybe we can just delete the file, and rely on the parent
to get a NOTE_EXTEND signal, and then realize that there's no
"detail.work" file, and process that? ... that's probably the simplest
TBH.  That way the parent and child can have no real relationship

The VNODE handler needs to minimize trolling through the directory, so
that it doesn't do so on every file creation. i.e. it should troll
through once, do the detail.work thing, remember there's a
detail.work... and then when it gets NOTE_EXTEND, only check that
there's a detail.work.  If it can't stat the detail.work file, it
needs to troll through the directory again.  Otherwise, the
detail.work reader is still busy, and the VNODE routine can ignore the
signal.

There's no documentation in `raddb/sites-available`.

We should have examples of calling other virtual servers:

    recv {
    	 call default.Accounting-Request {
	 	...
	 }
    }

Tho that configuration should be discouraged, as it can result in the
packets being written to the detail file again.  In v4 rlm_detail,
there is no logic to suppress that kind of configuration.

## Ideas

allow for multiple detail.work files, (detail.work1, detail.work2,
etc).  The VNODE handler can then spawn multiple children, allowing
for very fast reading of detail files!
