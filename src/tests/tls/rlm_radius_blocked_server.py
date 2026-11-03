#!/usr/bin/env python3
#
#  A RADIUS/TLS home server which stops reading.
#
#  The server accepts one TLS connection, completes the handshake, and then
#  does not read from the connection until the server receives SIGUSR1.  The
#  kernel buffers on both ends of the connection then fill, and the radius
#  module in the other process sees a blocked write.  After SIGUSR1 the server
#  reads until the peer closes the connection, and prints how many bytes the
#  server read.
#
#  The server does not speak RADIUS.  The server never replies, and does not
#  look at the data which the server reads.
#
#  The server prints one line to standard output for each step: "listening",
#  "handshake done", and "drained <N> bytes".
#
#  Usage: rlm_radius_blocked_server.py <port> <certdir>
#
#  The server needs ca.pem, server.pem and server.key in <certdir>.  The server
#  requires a client certificate, as unit_test_tls does.
#
#  $Id$
#
import signal
import socket
import ssl
import sys

port = int(sys.argv[1])
certdir = sys.argv[2]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

#
#  The TLS bio in the radius module is tested with TLS 1.2, see
#  rlm_radius_blocked.conf.
#
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(f"{certdir}/server.pem", f"{certdir}/server.key", password="whatever")
ctx.load_verify_locations(f"{certdir}/ca.pem")
ctx.verify_mode = ssl.CERT_REQUIRED

lsock = socket.socket()
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#
#  A small receive buffer, set before listen(), so that the accepted socket
#  has the small buffer.  The radius module sets a small send buffer, see
#  rlm_radius_blocked.conf.  Both buffers together hold a few kilobytes, so a
#  few packets fill the connection.
#
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
lsock.bind(("127.0.0.1", port))
lsock.listen(1)
print("listening", flush=True)

conn, _ = lsock.accept()
tconn = ctx.wrap_socket(conn, server_side=True)
print("handshake done", flush=True)

#
#  Block until the test says that the server can read.  signal.pause() returns
#  when a signal handler has run.
#
signal.signal(signal.SIGUSR1, lambda *args: None)
signal.pause()

total = 0
while True:
    data = tconn.recv(65536)
    if not data:
        break
    total += len(data)

print(f"drained {total} bytes", flush=True)
