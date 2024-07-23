# UDP

UDP is the source of a lot of problems with the server architecture.
UDP is connectionless, so all of the packets go through one socket.
This means that there is no TCP-like scaling with multiple UDP
sockets.

Mostly.

## Receive Side Steering

We can use Receive Side Steering in hardware, or implemented in
sofware in the kernel, is called Receive Packet Steering (RPS).  This
involves opening multiple sockets using the same destination ip/port,
all using `SO_REUSEPORT`.

When RSS is enabled, the kernel *should* then hash incoming packets,
and split them evenly across all sockets.  Even better, the kernel
hashes src/dst ip/port, so packets to/from the same IP/port all go to
the same socket.  Which helps a lot with RADIUS de-dup issues.

Cloudfare has some notes:  https://blog.cloudflare.com/how-to-achieve-low-latency/

Turn server has some notes: https://github.com/coturn/coturn/wiki/TURN-Performance-and-Load-Balance

This kind of scaling is likely the preferred method.

## Software equivalents

On systems without RSS, we can get TCP-like behavior with some hacks.

First, we open a wildcard socket (`INADDR_ANY` + port).  This socket
tracks *source* addresses, too.  When it receives a packet from an
unknown source IP/port (presuming the source passes the RADIUS client
checks), the socket allocates a "connection" structure.  It fills in
the src/dst ip/port, binds to it, and opens a new socket using
`SO_REUSEPORT`.

New packets for that connection will go to the connected socket, and
not to the wildcard one.  There may be a few packets for that
connection already in the wildcard packet queue, and the wildcard
handler has to take care of manually sending them over to the new connection.

In short, we can emulate (mostly) TCP connections via UDP.

We do not need to use connected sockets for DHCP.
