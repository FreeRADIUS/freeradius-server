"""
Helpers for the Bidirectional Forwarding Detection (BFD) tests in this
directory.

The tests start a radiusd with one BFD peer defined, and then act as that
peer from a UDP socket.  They send hand-built BFD Control packets to the
server and check the packets that come back.  The packet layout and the rules
checked are those of RFC 5880.

The tests read the state of the server in two ways:

  - A packet with the Poll bit set makes the server answer at once with a
    packet that has the Final bit set and carries the current state of the
    server (RFC 5880 Section 6.5).  This method is quick and does not depend
    on timers.

  - The server also sends periodic packets without being asked.  The tests in
    `timing.py` wait for the periodic packets.

Environment variables:

  `BFD_RADIUSD`  The command that starts radiusd.  Defaults to
                 `scripts/bin/radiusd` in the source tree.
  `OUTPUT`       The directory for the configuration and logs of each test.
                 Defaults to a new temporary directory.
"""

import dataclasses
import enum
import hashlib
import os
import pathlib
import re
import select
import shlex
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

HEADER_LEN = 24
LOOPBACK = "127.0.0.1"

# Longest we wait for a packet which should arrive.
ANSWER_TIMEOUT = 2.0

# How long we wait before deciding that a packet was discarded.
DISCARD_TIMEOUT = 0.3


class State(enum.IntEnum):
    """BFD session states, RFC 5880 Section 4.1."""
    ADMIN_DOWN = 0
    DOWN = 1
    INIT = 2
    UP = 3


class Diag(enum.IntEnum):
    """BFD diagnostic codes, RFC 5880 Section 4.1."""
    NONE = 0
    CONTROL_EXPIRED = 1
    ECHO_FAILED = 2
    NEIGHBOR_DOWN = 3
    FORWARDING_RESET = 4
    PATH_DOWN = 5
    CONCAT_PATH_DOWN = 6
    ADMIN_DOWN = 7
    REVERSE_CONCAT_PATH_DOWN = 8


class AuthType(enum.IntEnum):
    """BFD authentication types, RFC 5880 Section 4.1."""
    SIMPLE = 1
    KEYED_MD5 = 2
    MET_KEYED_MD5 = 3
    KEYED_SHA1 = 4
    MET_KEYED_SHA1 = 5


# The name used for each type in the 'auth_type' configuration item.
AUTH_CONFIG_NAMES = {
    None: "none",
    AuthType.SIMPLE: "simple",
    AuthType.KEYED_MD5: "keyed-md5",
    AuthType.MET_KEYED_MD5: "met-keyed-md5",
    AuthType.KEYED_SHA1: "keyed-sha1",
    AuthType.MET_KEYED_SHA1: "met-keyed-sha1",
}

# Digest sizes, which are also the size the secret is padded to.
DIGEST_SIZES = {
    AuthType.KEYED_MD5: 16,
    AuthType.MET_KEYED_MD5: 16,
    AuthType.KEYED_SHA1: 20,
    AuthType.MET_KEYED_SHA1: 20,
}


@dataclasses.dataclass
class BfdPacket:
    """
    One BFD Control packet, with the fields named as in RFC 5880.

    Every field can be set to an invalid value, so that tests can build
    packets which a correct server must discard.
    """
    version: int = 1
    diag: int = Diag.NONE
    state: int = State.DOWN
    poll: bool = False
    final: bool = False
    cpi: bool = False
    auth_present: bool = None       # None means "set if auth_type is set"
    demand: bool = False
    multipoint: bool = False
    detect_mult: int = 3
    length: int = None              # None means "calculate it"
    my_disc: int = 0x5eed0001
    your_disc: int = 0
    desired_min_tx: int = 1000000
    required_min_rx: int = 1000000
    echo_rx: int = 0
    auth_type: int = None
    key_id: int = 0
    sequence: int = 0
    password: bytes = b""
    digest: bytes = None            # None means "calculate it"
    auth_len: int = None            # None means "calculate it"

    # Set on received packets.
    raw: bytes = dataclasses.field(default=None, compare=False)
    when: float = dataclasses.field(default=None, compare=False)

    def pack(self, secret: bytes = None) -> bytes:
        """Encode the packet.  The secret is used to sign it."""
        body = b""
        auth_bit = self.auth_present

        if auth_bit is None:
            auth_bit = self.auth_type is not None

        if self.auth_type == AuthType.SIMPLE:
            auth_len = 3 + len(self.password)
            body = struct.pack(">BBB", self.auth_type,
                               self.auth_len or auth_len,
                               self.key_id) + self.password

        elif self.auth_type is not None:
            size = DIGEST_SIZES[self.auth_type]
            auth_len = 8 + size
            body = struct.pack(">BBBBI", self.auth_type,
                               self.auth_len or auth_len,
                               self.key_id, 0, self.sequence)
            body += (self.digest if self.digest is not None
                     else (secret or b"").ljust(size, b"\0"))

        length = self.length if self.length is not None \
            else HEADER_LEN + len(body)

        header = struct.pack(
            ">BBBBIIIII",
            (self.version << 5) | self.diag,
            ((self.state << 6) | (self.poll << 5) | (self.final << 4) |
             (self.cpi << 3) | (auth_bit << 2) | (self.demand << 1) |
             self.multipoint),
            self.detect_mult, length, self.my_disc, self.your_disc,
            self.desired_min_tx, self.required_min_rx, self.echo_rx)

        raw = header + body

        # RFC 5880 Sections 6.7.3 and 6.7.4: the digest covers the whole
        # packet, with the padded secret in place of the digest.
        if self.auth_type in DIGEST_SIZES and self.digest is None:
            hasher = (hashlib.md5 if self.auth_type in
                      (AuthType.KEYED_MD5, AuthType.MET_KEYED_MD5)
                      else hashlib.sha1)
            size = DIGEST_SIZES[self.auth_type]
            raw = raw[:-size] + hasher(raw).digest()

        return raw

    @staticmethod
    def parse(data: bytes) -> "BfdPacket":
        """Decode a packet.  Raises ValueError if it is too short."""
        if len(data) < HEADER_LEN:
            raise ValueError("short packet")

        (first, flags, mult, length, my_disc, your_disc, tx, rx,
         echo) = struct.unpack(">BBBBIIIII", data[:HEADER_LEN])

        pkt = BfdPacket(
            version=first >> 5, diag=first & 0x1f, state=flags >> 6,
            poll=bool(flags & 0x20), final=bool(flags & 0x10),
            cpi=bool(flags & 0x08), auth_present=bool(flags & 0x04),
            demand=bool(flags & 0x02), multipoint=bool(flags & 0x01),
            detect_mult=mult, length=length, my_disc=my_disc,
            your_disc=your_disc, desired_min_tx=tx, required_min_rx=rx,
            echo_rx=echo, raw=data, when=time.monotonic())

        if pkt.auth_present and len(data) >= HEADER_LEN + 3:
            pkt.auth_type = data[24]
            pkt.auth_len = data[25]
            pkt.key_id = data[26]

            if pkt.auth_type == AuthType.SIMPLE:
                pkt.password = data[27:HEADER_LEN + pkt.auth_len]

            elif pkt.auth_type in DIGEST_SIZES:
                size = DIGEST_SIZES[pkt.auth_type]
                pkt.sequence = struct.unpack(">I", data[28:32])[0]
                pkt.digest = data[32:32 + size]

        return pkt

    @staticmethod
    def digest_ok(raw: bytes, secret: bytes) -> bool:
        """Check the digest of a received keyed MD5 or SHA1 packet."""
        pkt = BfdPacket.parse(raw)
        size = DIGEST_SIZES[pkt.auth_type]
        signed = raw[:pkt.length - size] + secret.ljust(size, b"\0")
        hasher = (hashlib.md5 if size == 16 else hashlib.sha1)

        return hasher(signed).digest() == pkt.digest


@dataclasses.dataclass
class ServerConfig:
    """
    The configuration that the test writes for the one peer of the test server.
    """
    auth_type: int = None
    secret: str = "testing123"
    tx: str = "1s"                  # peer min_transmit_interval
    rx: str = "250ms"               # peer min_receive_interval
    max_timeouts: int = 3
    demand: bool = False
    only_state_changes: bool = True
    sections: str = ""              # extra text for the virtual server


class BfdServer:
    """A radiusd with one BFD listener and one peer."""

    READY = "Ready to process requests"

    # The server refuses to start with no processing sections at all.
    DEFAULT_SECTIONS = "\trecv Down {\n\t\tnoop\n\t}\n"

    def __init__(self, directory: pathlib.Path, config: ServerConfig,
                 listen_port: int, peer_port: int) -> None:
        self.directory = directory
        self.config = config
        self.listen_port = listen_port
        self.peer_port = peer_port

        self.proc = None
        self.reader = None
        self.lines = []
        self.lock = threading.Condition()
        self.exited = False
        self.log_path = directory / "radiusd.log"

    def write_config(self) -> None:
        """Write radiusd.conf for the server."""
        cfg = self.config
        secret = ""

        if cfg.auth_type is not None:
            secret = f'secret = "{cfg.secret}"'

        text = f"""
run_dir = {self.directory}

security {{
	allow_vulnerable_openssl = yes
	allow_core_dumps = yes
}}

modules {{
	always noop {{
		rcode = noop
	}}
}}

server bfd {{
	namespace = bfd

	bfd {{
	}}

	listen {{
		transport = udp

		udp {{
			ipaddr = {LOOPBACK}
			port = {self.listen_port}
			only_state_changes = {'yes' if cfg.only_state_changes else 'no'}
		}}
	}}

	peer test {{
		ipaddr = {LOOPBACK}
		proto = udp
		port = {self.peer_port}
		auth_type = {AUTH_CONFIG_NAMES[cfg.auth_type]}
		{secret}
		min_transmit_interval = {cfg.tx}
		min_receive_interval = {cfg.rx}
		max_timeouts = {cfg.max_timeouts}
		demand = {'yes' if cfg.demand else 'no'}
	}}

{cfg.sections or self.DEFAULT_SECTIONS}
}}
"""
        (self.directory / "radiusd.conf").write_text(text)

    def read_output(self, stream) -> None:
        """Copy the server output to the log until the server exits."""
        with stream, open(self.log_path, "w") as log:
            for line in stream:
                log.write(line)
                log.flush()

                with self.lock:
                    self.lines.append(line.rstrip("\n"))
                    self.lock.notify_all()

        with self.lock:
            self.exited = True
            self.lock.notify_all()

    def start(self) -> None:
        """Start the server, and return when it is ready."""
        root = pathlib.Path(__file__).resolve().parents[3]
        command = shlex.split(os.environ.get(
            "BFD_RADIUSD", str(root / "scripts" / "bin" / "radiusd")))

        self.write_config()

        self.proc = subprocess.Popen(
            command + ["-X", "-d", str(self.directory), "-n", "radiusd"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            cwd=root)

        self.reader = threading.Thread(
            target=self.read_output, args=(self.proc.stdout,), daemon=True)
        self.reader.start()

        if self.wait_for_log(self.READY, 20.0) is None:
            self.stop()
            raise RuntimeError(f"radiusd did not start, see {self.log_path}")

    def stop(self) -> None:
        """Stop the server."""
        if self.proc is None:
            return

        if self.proc.poll() is None:
            self.proc.terminate()

            try:
                self.proc.wait(5.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

        self.reader.join(5.0)
        self.proc = None

    def log_mark(self) -> int:
        """Return a position in the log, for use with wait_for_log()."""
        with self.lock:
            return len(self.lines)

    def wait_for_log(self, pattern: str, timeout: float,
                     after: int = 0) -> re.Match:
        """
        Wait for a log line matching the pattern.  Returns None if none
        arrives, or if the server exits first.
        """
        regex = re.compile(pattern)
        deadline = time.monotonic() + timeout
        index = after

        with self.lock:
            while True:
                while index < len(self.lines):
                    found = regex.search(self.lines[index])
                    index += 1

                    if found:
                        return found

                remaining = deadline - time.monotonic()

                if remaining <= 0 or self.exited:
                    return None

                self.lock.wait(remaining)


class BfdPeer:
    """
    The end of the BFD session that the test controls.  The end is a UDP
    socket.
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOOPBACK, 0))
        self.port = self.sock.getsockname()[1]

    def close(self) -> None:
        """Close the socket."""
        self.sock.close()

    def drain(self) -> None:
        """Throw away every packet which has already arrived."""
        while select.select([self.sock], [], [], 0)[0]:
            self.sock.recvfrom(4096)

    def send(self, data: bytes, port: int) -> None:
        """Send raw bytes to the server."""
        self.sock.sendto(data, (LOOPBACK, port))

    def receive(self, accept, timeout: float) -> BfdPacket:
        """
        Return the first received packet for which accept(packet) is true.
        Returns None if there is none within the timeout.
        """
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                return None

            ready, _, _ = select.select([self.sock], [], [], remaining)

            if not ready:
                return None

            data, _ = self.sock.recvfrom(4096)

            try:
                pkt = BfdPacket.parse(data)
            except ValueError:
                continue

            if accept(pkt):
                return pkt


def swap32(value: int) -> int:
    """Reverse the byte order of a 32 bit value."""
    return int.from_bytes(value.to_bytes(4, "big"), "little")


def free_udp_port() -> int:
    """Return a UDP port number which is not in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((LOOPBACK, 0))
        return sock.getsockname()[1]


class AbstractBfdTest(unittest.TestCase):
    """
    Base class for the BFD tests.  Every test starts its own server.  The
    server keeps only one session for each peer address, and a session carries
    state from one packet to the next.  Because of that, a shared server would
    carry state from one test to the next.

    A subclass sets `CONFIG` to change how the peer is configured.
    """
    CONFIG = ServerConfig()

    def setUp(self) -> None:
        base = os.environ.get("OUTPUT") or tempfile.mkdtemp(prefix="bfd-")
        directory = pathlib.Path(base) / self.id().replace("__main__.", "")
        directory.mkdir(parents=True, exist_ok=True)

        self.peer = BfdPeer()
        self.addCleanup(self.peer.close)

        self.server = BfdServer(directory, self.CONFIG, free_udp_port(),
                                self.peer.port)
        self.addCleanup(self.server.stop)
        self.server.start()

        # Our discriminator, and the next authentication sequence number.
        self.disc = 0x5eed0001
        self.sequence = 1000

    @property
    def secret(self) -> bytes:
        """The shared secret, as bytes."""
        return self.CONFIG.secret.encode()

    def packet(self, **fields) -> BfdPacket:
        """
        Build a packet from the peer, signed the way the server expects.
        Any field can be overridden.
        """
        fields.setdefault("my_disc", self.disc)
        fields.setdefault("auth_type", self.CONFIG.auth_type)

        if self.CONFIG.auth_type == AuthType.SIMPLE:
            fields.setdefault("password", self.secret)

        if self.CONFIG.auth_type in DIGEST_SIZES:
            fields.setdefault("sequence", self.sequence)
            self.sequence += 1

        return BfdPacket(**fields)

    def send(self, pkt: BfdPacket) -> None:
        """Send a packet to the server."""
        self.peer.send(pkt.pack(self.secret), self.server.listen_port)

    def probe(self, pkt: BfdPacket) -> BfdPacket:
        """
        Send the packet with the Poll bit set, and return the Final
        packet which the server sends back.  Returns None if there is no
        answer, which means the server discarded the packet.
        """
        pkt.poll = True
        self.send(pkt)

        return self.peer.receive(lambda p: p.final, DISCARD_TIMEOUT)

    def assertAnswered(self, pkt: BfdPacket) -> BfdPacket:
        """Check that the server answers a polled packet."""
        reply = self.probe(pkt)
        self.assertIsNotNone(
            reply, f"no answer to {pkt}, see {self.server.log_path}")

        return reply

    def assertDiscarded(self, pkt: BfdPacket) -> None:
        """
        Check that the server ignores a polled packet.  A correct poll
        first shows that the server is answering at all, so that silence
        means something.
        """
        self.assertAnswered(self.packet(state=State.DOWN))

        reply = self.probe(pkt)
        self.assertIsNone(
            reply, f"server answered {pkt} with {reply}")

    def server_disc(self) -> int:
        """Learn the server's discriminator, without changing its state."""
        pkt = self.peer.receive(lambda p: not p.final, 3.0)
        self.assertIsNotNone(pkt, "server sent no periodic packet")

        return pkt.my_disc

    def bring_up(self, **fields) -> BfdPacket:
        """
        Run the three way handshake of RFC 5880 Section 6.8.1 so that the
        server session is Up.  Returns the last answer from the server.
        The fields are added to both packets sent.
        """
        reply = self.assertAnswered(self.packet(state=State.DOWN, **fields))
        self.assertEqual(reply.state, State.INIT)

        reply = self.assertAnswered(self.packet(
            state=State.INIT, your_disc=reply.my_disc, **fields))
        self.assertEqual(reply.state, State.UP)

        return reply
