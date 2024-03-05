# The FD bio

The file descriptor bio abstracts reads / writes over file
descriptors.  The goal is for applications to be able to get a file
descriptor bio, and then just call raw read / write routines, similar
to the Posix `read()` and `write()` functions.  The difference is that
the bio routines _abstract_ all of the issues with file descriptors.

For example, file descriptors can refer to files, sockets (stream or
datagram), IPv4, IPv6, Unix domain sockets, etc.  Each of those file
descriptor types has a different set of requirements for
initialization, and even for reading and writing.

The simplest and perhaps most frustrating difference between the types
of sockets is that when the Posix `read()` function returns `0`.  That
value has _different meanings_ for stream and datagram sockets.  For
stream sockets, it means "EOF", and the socket should be closed.  For
datagram sockets, it means "read() returned no data".

In our bio implementation, `read()` of `0` always means "no data".
Signally EOF is an error path, where the `read()` function returns an
EOF error.

Similarly, initializing a socket requires a number of steps, which are
all different for IPv4, IPv6, and whether the socket was connected or
unconnected.  Perhaps the underlying socket is a connected stream
socket, in which case IO is essentially just `read()` and `write()`.
Or maybe the socket is an unconnected datagram socket, in which case
IO has to use the `udpfromto` path to obtain the src/dst IP/port
information for each packet.

All of these differences are abstracted away with the bio API.  The
caller simply declares a `fr_bio_fd_config_t` data structure, fills it
in with the appropriate data, and calls `fr_bio_fd_alloc()`.  The FD
bio code determines what kind of file descriptor to open, and then
initializes it.

The caller gets returned a bio which can then be used for basic read /
write operations, independent of the underlying file descriptor type.

There is no API to query the state of the FD bio.  Instead, the caller
can get a copy of the internal `fr_bio_fd_info_t` data structure,
which contains all of the "raw" data needed by the application.  The
caller can see whether or not the bio is at EOF, or if it is blocked
for read / write operations.

The file descriptor bio does _not_ manage packets.  If there is a
partial write, it returns a partial write.  It is up to the
application (or another bio) to manage packet-oriented data.
