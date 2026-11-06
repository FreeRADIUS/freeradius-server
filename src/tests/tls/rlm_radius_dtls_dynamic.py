#!/usr/bin/env python3
#
#  Send one Access-Request over TCP to radiusd, then wait for radiusd to
#  close the connection or for 30 seconds to pass.
#  `rlm_radius_dtls_dynamic.sh` runs `rlm_radius_dtls_dynamic.py` once radiusd
#  is ready.  The Access-Request makes the `radius` module open a DTLS
#  connection to the destination that `rlm_radius_dtls_dynamic.conf` passes
#  to `%home.sendto.ipaddr()`.
#
#  Environment:
#    LPORT  TCP port where radiusd listens, on 127.0.0.1
#
#  The program exits with status 0 when the program has written the whole
#  packet.
#
#  $Id$
#
import os
import socket
import struct
import sys

attrs = b"\x01" + bytes([2 + 4]) + b"test"
packet = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + os.urandom(16) + attrs

with socket.create_connection(("127.0.0.1", int(os.environ["LPORT"])), timeout=10) as sock:
    sock.sendall(packet)
    #
    #  radiusd does not send a reply.  Wait for radiusd to close the connection.
    #
    sock.settimeout(30)
    try:
        sock.recv(4096)
    except (socket.timeout, OSError):
        pass

sys.exit(0)
