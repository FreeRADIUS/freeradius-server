# The Memory Bio

The memory bio does read / write buffering for a "next" bio.  Where
the file descriptor bio does no buffering, the memory bio adds that
capability.

In its simplest incarnation, the memory bio allows for controllable
buffering on read and write.

The read functions try to fill the memory buffer on each read.  The
application can then read smaller bits of data from the memory buffer,
which avoids extra system calls.

The write functions try to bypass the memory buffer as much as
possible.  If the memory buffers are empty, the `write()` call writes
directly to the next bio block, and avoids memory copies.  The data is
cached only if the next block returns a partial write.  In which case
the partial data is cached, and is written _before_ any data from
subsequent calls to `write()`.

Data in the buffers can always be flushed via passing a `NULL` pointer to the
`write()` routine.

## Packet-based reads

The memory bio supports a function`fr_bio_mem_set_verify()`, which
sets a "verification" function.  When the application calls `read()`,
the memory bio reads the data into an intermediate buffer, and then
calls the verify function.  That function can return the size of the
packet to read, or other options like "discard data", or "want more
data", or "have full packet".  That way the application only sees
whole packets.

The application then calls the main bio `read()` routines, which
(eventually) reads raw data from somewhere.  When that data is at
least a full packet, it is returned to the application.
