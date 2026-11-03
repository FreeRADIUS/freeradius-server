#!/usr/bin/env python3
#
#  A RADIUS/TLS or RADIUS/TCP home server which stops reading.
#
#  The server accepts one connection, completes the TLS handshake when the
#  transport is TLS, and then
#  does not read from the connection until the server receives SIGUSR1.  The
#  kernel buffers on both ends of the connection then fill, and the radius
#  module in the other process sees a blocked write.  After SIGUSR1 the server
#  reads until the peer closes the connection, and prints how many bytes the
#  server read.
#
#  The server does not speak RADIUS.  The server never replies.  The server
#  checks only the framing of the data which the server reads: each packet
#  starts with a code of 1 (Access-Request) and a length, and the next packet
#  starts right after the length.  A radius module which loses part of a packet
#  when a write blocks breaks the framing.  The radius module closes the
#  connection at exit, so the last packet may be partial.
#
#  The server prints one line to standard output for each step: "listening",
#  "handshake done" (for TLS) or "connected" (for TCP), "drained <N> bytes",
#  and "framing ok <N> packets" or "framing bad at offset <N>".
#
#  Usage: rlm_radius_blocked_server.py <port> <certdir> [tcp]
#
#  For TLS, the server needs ca.pem, server.pem and server.key in <certdir>.
#  The server requires a client certificate, as unit_test_tls does.  With the
#  "tcp" argument the server does not use TLS, and does not read <certdir>.
#
#  $Id$
#
import signal
import socket
import ssl
import sys

port = int(sys.argv[1])
certdir = sys.argv[2]
use_tls = (sys.argv[3:] != ["tcp"])

if use_tls:
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
if use_tls:
    tconn = ctx.wrap_socket(conn, server_side=True)
    print("handshake done", flush=True)
else:
    tconn = conn
    print("connected", flush=True)

#
#  Block until the test says that the server can read.  signal.pause() returns
#  when a signal handler has run.
#
signal.signal(signal.SIGUSR1, lambda *args: None)
signal.pause()

stream = bytearray()
while True:
    data = tconn.recv(65536)
    if not data:
        break
    stream += data

print(f"drained {len(stream)} bytes", flush=True)

offset = 0
packets = 0
while offset + 4 <= len(stream):
    code = stream[offset]
    length = (stream[offset + 2] << 8) | stream[offset + 3]
    if code != 1 or length < 20:
        print(f"framing bad at offset {offset}", flush=True)
        sys.exit(0)

    #
    #  A packet which the radius module did not finish before the connection closed.
    #
    if offset + length > len(stream):
        break

    offset += length
    packets += 1

print(f"framing ok {packets} packets", flush=True)
