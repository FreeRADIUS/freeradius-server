#!/usr/bin/env python3
"""Send one ARP request from the client container and report the outcome.

Usage:
    arp-request.py <step> <target address> [<timeout seconds>]

The script sends a broadcast ARP request for the target address from
eth0, with the address of the container as the sender, and waits up to
the timeout (default 2 seconds) for a reply about the target.  Every
other packet, the request itself included, is skipped.  The script then
appends the line

    client-<step> {"reply": "yes"|"no", "sender_mac": "<mac>"}

to the file that the test framework watches.  `sender_mac` is the
hardware address the reply carries as the sender, and is empty without a
reply.
"""

import fcntl
import os
import select
import socket
import struct
import sys
import time

ETH_P_ARP = 0x0806
SIOCGIFADDR = 0x8915
INTERFACE = "eth0"
BROADCAST = b"\xff" * 6


def interface_addresses(sock, interface):
    """Return the hardware and IPv4 addresses of the interface as bytes."""
    with open(f"/sys/class/net/{interface}/address") as f:
        mac = bytes.fromhex(f.read().strip().replace(":", ""))

    request = struct.pack("256s", interface.encode())
    ip = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24]

    return mac, ip


def reply_wait(sock, target, timeout):
    """Return the sender hardware address of a reply about target, or None."""
    deadline = time.monotonic() + timeout

    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None

        readable, _, _ = select.select([sock], [], [], left)
        if not readable:
            return None

        frame = sock.recv(2048)
        if len(frame) < 14 + 28:
            continue

        ether_type = struct.unpack("!H", frame[12:14])[0]
        if ether_type != ETH_P_ARP:
            continue

        #
        #  ARP header after the 14 byte ethernet header: hardware and
        #  protocol types and lengths (6 bytes), opcode, sender hardware
        #  and protocol addresses.
        #
        op, sha, spa = struct.unpack("!6xH6s4s", frame[14:14 + 18])
        if op != 2 or spa != target:
            continue

        return sha


def main():
    if len(sys.argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2

    step = sys.argv[1]
    target = socket.inet_aton(sys.argv[2])
    timeout = float(sys.argv[3]) if len(sys.argv) == 4 else 2.0

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    sock.bind((INTERFACE, 0))
    mac, ip = interface_addresses(sock, INTERFACE)

    frame = struct.pack("!6s6sH", BROADCAST, mac, ETH_P_ARP)
    frame += struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac, ip, b"\x00" * 6, target)
    sock.send(frame)

    sha = reply_wait(sock, target, timeout)
    sender_mac = ":".join(f"{b:02x}" for b in sha) if sha else ""

    trigger_file = f"/var/run/multi-server/{os.environ['TEST_PROJECT_NAME']}.txt"
    with open(trigger_file, "a") as f:
        f.write(f'client-{step} {{"reply": "{"yes" if sha else "no"}", "sender_mac": "{sender_mac}"}}\n')

    return 0


if __name__ == "__main__":
    sys.exit(main())
