#!/usr/bin/env python3
#
#  Tests for the retry and timeout rules of the `radius` module.
#
#  Each test has a configuration file of the same name, and a function in
#  this file.  The configuration file starts one `radius` module in one mode,
#  over one transport.  The test starts radiusd with the configuration file,
#  and either checks the configuration (the "config_" tests), or sends
#  packets to the UDP listener of radiusd.  The `radius` module then sends
#  the packets to a home server which this program runs.  The home server
#  records every packet that it receives.
#
#  The timeouts of the tests are the lower bounds that the module accepts, so
#  that each test runs for a few seconds.
#
#  Environment:
#    TEST      name of the test, which is also the name of the configuration file
#    RADIUSD   command which runs radiusd, possibly several words
#    OUTPUT    directory for the log files and the receipt file
#    CONFDIR   directory holding the configuration files
#    DICT_PATH dictionary directory
#    PORT      port of the home server
#    LPORT     UDP port where radiusd listens
#    CERTDIR   directory holding the test certificates, which the TLS home server needs
#
#  Exit status is zero when every check passes.  The program then writes the
#  receipt file.
#
#  $Id$
#
import hashlib
import os
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

test = os.environ["TEST"]
radiusd = shlex.split(os.environ["RADIUSD"])
output = os.environ["OUTPUT"]
confdir = os.environ["CONFDIR"]
dict_path = os.environ["DICT_PATH"]
port = int(os.environ["PORT"])
lport = int(os.environ["LPORT"])
certdir = os.environ.get("CERTDIR", "")

SECRET = b"testing123"

#
#  The secret when the configuration file has none, and the transport is TLS (RFC 6614 Section 2.3).
#
SECRET_TLS = b"radsec"

ALPN_RADIUS_1_0 = "radius/1.0"
ALPN_RADIUS_1_1 = "radius/1.1"

MESSAGE_AUTHENTICATOR = 80
CHAP_PASSWORD = 3
CHAP_CHALLENGE = 60

#
#  Value of "max_rtx_duration" in the configuration files of the tests which
#  wait for a timeout.
#
MRD = 5

#
#  The message which the `radius` module logs when a packet reaches
#  "max_rtx_duration", and the message when the packet reaches "max_rtx_count".
#
MSG_MRD = "Reached maximum_retransmit_duration"
MSG_MRC = "Reached maximum_retransmit_count"
MSG_ZOMBIE = "Entering Zombie state"
MSG_DEAD = "marking connection"
MSG_OPEN = "Connection open"
MSG_ACTIVE = "marking connection as active"

#
#  The packet code of a status check.
#
STATUS_SERVER = 12
MSG_DUP_IGNORED = "Ignoring retransmit from client"

failed = []


def check(ok, message):
    print(("ok: " if ok else "FAILED: ") + message, flush=True)
    if not ok:
        failed.append(message)
    return ok


def access_request(ident):
    """An Access-Request with one User-Name attribute, and a random authenticator."""
    attrs = b"\x01" + bytes([2 + 8]) + b"user%04d" % ident
    return struct.pack("!BBH", 1, ident & 0xff, 20 + len(attrs)) + os.urandom(16) + attrs


def user_of(packet):
    """The User-Name of a packet, or None."""
    pos = 20
    while pos + 2 <= len(packet):
        if packet[pos] == 1:
            return packet[pos + 2:pos + packet[pos + 1]].decode()
        pos += packet[pos + 1]
    return None


def attrs_of(packet):
    """The attributes of a packet, as a list of (type, value)."""
    attrs = []
    pos = 20
    while pos + 2 <= len(packet):
        attrs.append((packet[pos], packet[pos + 2:pos + packet[pos + 1]]))
        pos += packet[pos + 1]
    return attrs


def reply_to(packet, secret=SECRET):
    """An Access-Accept for the Access-Request, with a valid Response-Authenticator."""
    code, ident, length = struct.unpack("!BBH", packet[:4])
    head = struct.pack("!BBH", 2, ident, 20)
    return head + hashlib.md5(head + packet[4:20] + secret).digest()


def reply_to_1_1(packet):
    """
    An Access-Accept for a RADIUS/1.1 Access-Request.  The reply is not signed, and
    copies the Token and the reserved octets from the request (RFC 9765 Section 4).
    """
    return struct.pack("!BBH", 2, 0, 20) + packet[4:20]


class Home:
    """
    A home server over UDP or TCP, which records the time of every packet.

    The home server drops the first "drop" packets, and replies to every later
    packet when "reply" is true.

    The "tls" transport is RADIUS/TLS over TLS 1.3.  "alpn" is the list of ALPN
    names that the home server offers, or None when the home server does not use
    ALPN.  "selected" is the name which the last connection negotiated.  A reply
    to a packet from a connection which negotiated "radius/1.1" is a RADIUS/1.1
    packet.  "packets" holds every packet that is not a status check.

    A Status-Server packet is a status check from the module.  The home server
    does not count the packet in "times".  The home server replies to a status
    check only while "status_reply" is true.
    """

    def __init__(self, transport, drop=0, reply=False, alpn=None):
        self.transport = transport
        self.alpn = alpn
        self.selected = None
        self.handshake_errors = []
        self.packets = []
        self.drop = drop
        self.reply = reply
        self.status_reply = False
        self.reply_users = set()
        self.times = []
        self.status_times = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        if transport != "udp":
            self.sock.listen(1)
        self.stop = False
        run = {"udp": self.run_udp, "tcp": self.run_tcp, "tls": self.run_tls}[transport]
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def seen(self, packet, send):
        if packet[0] == STATUS_SERVER:
            self.status_times.append(time.monotonic())
            if self.status_reply:
                send(reply_to(packet))
            return

        self.times.append(time.monotonic())
        self.packets.append(packet)
        if (self.reply and len(self.times) > self.drop) or user_of(packet) in self.reply_users:
            if self.selected == ALPN_RADIUS_1_1:
                send(reply_to_1_1(packet))
            else:
                send(reply_to(packet, SECRET_TLS if self.transport == "tls" else SECRET))

    def run_udp(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                packet, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            self.seen(packet, lambda data: self.sock.sendto(data, addr))

    def run_tcp(self):
        self.sock.settimeout(0.2)
        conn = None
        while not self.stop and conn is None:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue

        if conn is None:
            return

        self.serve(conn)

    def serve(self, conn):
        """Read RADIUS packets from a stream connection until the peer closes the connection."""
        conn.settimeout(0.2)
        data = b""
        while not self.stop:
            try:
                more = conn.recv(4096)
            except socket.timeout:
                continue
            except (ssl.SSLError, OSError):
                break
            if not more:
                break
            data += more
            while len(data) >= 4:
                length = struct.unpack("!H", data[2:4])[0]
                if len(data) < length:
                    break
                self.seen(data[:length], conn.sendall)
                data = data[length:]

        conn.close()

    def run_tls(self):
        """
        Accept TLS connections one after the other, because the module opens
        another connection after a connection fails.  The home server does not
        ask for a client certificate.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(f"{certdir}/server.pem", f"{certdir}/server.key", password="whatever")
        if self.alpn:
            ctx.set_alpn_protocols(self.alpn)

        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue

            conn.settimeout(5)
            try:
                tconn = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self.handshake_errors.append(str(e))
                conn.close()
                continue

            self.selected = tconn.selected_alpn_protocol()
            self.serve(tconn)

    @property
    def count(self):
        return len(self.times)

    def close(self):
        self.stop = True
        self.thread.join()
        self.sock.close()


class Radiusd:
    """radiusd, with the output of radiusd kept in "lines"."""

    def __init__(self, extra):
        self.lines = []
        self.events = {}
        self.lock = threading.Lock()
        env = dict(os.environ, PORT=str(port), LPORT=str(lport))
        self.proc = subprocess.Popen(radiusd + ["-d", confdir, "-D", dict_path, "-n", test] + extra + ["-l", "stdout"],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        for line in self.proc.stdout:
            with self.lock:
                self.lines.append(line)
                for text, event in self.events.items():
                    if text in line:
                        event.set()

        with self.lock:
            for event in self.events.values():
                event.set()

    def found(self, text):
        with self.lock:
            return any(text in line for line in self.lines)

    def wait_for(self, text, timeout):
        """Wait until radiusd logs the text.  Returns true if radiusd logged the text."""
        with self.lock:
            event = self.events.setdefault(text, threading.Event())
            if any(text in line for line in self.lines):
                event.set()

        event.wait(timeout)
        return self.found(text)

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            failed.append("radiusd did not exit after SIGTERM")

        self.thread.join()

        check(not any(("ASSERT FAILED" in line) or ("CAUGHT SIGNAL" in line) for line in self.lines),
              "radiusd logged no assertion or signal")
        if not check(self.proc.returncode == 0, f"radiusd exited with status {self.proc.returncode}"):
            self.show_failure()

    def show_failure(self):
        """
        Print the output of radiusd which explains a bad exit status.  A sanitizer writes its report
        to the same stream as radiusd, and the report starts at the first line that names the sanitizer.
        Without a report, the end of the output is the best clue.
        """
        start = next((i for i, line in enumerate(self.lines)
                      if ("Sanitizer" in line) or ("runtime error" in line)), max(0, len(self.lines) - 60))
        print("--- output of radiusd, from line %d ---" % (start + 1), flush=True)
        print("".join(self.lines[start:start + 300]), end="", flush=True)
        print("--- end of the output of radiusd ---", flush=True)


def start():
    radiusd = Radiusd(["-msx", "-e", "60"])
    check(radiusd.wait_for("Ready to process requests", 30), "radiusd is ready")
    return radiusd


def finish(lines):
    with open(f"{output}/{test}.log", "w") as f:
        f.writelines(lines)

    if failed:
        print(f"{test}: failed: " + "; ".join(failed))
        sys.exit(1)

    open(f"{output}/{test}.receipt", "w").close()
    sys.exit(0)


def send(ident, packet=None, sock=None):
    """
    Send an Access-Request to radiusd, like a NAS does.

    A duplicate has to come from the same source port as the original packet, so
    the caller passes the socket which sent the original packet.
    """
    sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = packet or access_request(ident)
    sock.sendto(packet, ("127.0.0.1", lport))
    return sock, packet


def run_config_check():
    """Run `radiusd -C`.  The output has the warnings of the configuration check."""
    env = dict(os.environ, PORT=str(port), LPORT=str(lport))
    proc = subprocess.run(radiusd + ["-d", confdir, "-D", dict_path, "-n", test, "-C", "-l", "stdout"],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    return proc.returncode, proc.stdout


#
#  The tests.
#

def udp_client_retry():
    """
    mode = client over UDP.  The home server drops the first two packets.  The
    module retransmits at each retry interval, so the third packet gets a
    reply, and the request completes.
    """
    home = Home("udp", drop=2, reply=True)
    radiusd = start()
    sock, _ = send(1)
    sock.settimeout(20)

    try:
        reply = sock.recv(4096)
    except socket.timeout:
        reply = b""

    check(home.count == 3, f"home server received three packets ({home.count})")
    check(len(reply) > 0, "NAS received a reply after the retransmissions")
    check(not radiusd.found(MSG_MRD) and not radiusd.found(MSG_MRC), "request did not reach a final timeout")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def proxy_once(transport):
    """
    The home server never replies.  The module sends the packet once, in spite
    of max_rtx_count = 5 and initial_rtx_time = 1, and the request fails at
    max_rtx_duration.
    """
    home = Home(transport)
    radiusd = start()
    sent = time.monotonic()
    send(1)

    check(radiusd.wait_for(MSG_MRD, MRD + 10), "request failed at max_rtx_duration")
    elapsed = time.monotonic() - sent
    check(MRD - 1 <= elapsed <= MRD + 3, f"request failed after {elapsed:.1f} seconds, max_rtx_duration is {MRD}")
    check(not radiusd.found(MSG_MRC), "request did not reach max_rtx_count")
    check(not radiusd.found(MSG_ZOMBIE), "one lost request did not mark the connection zombie")

    #
    #  Wait past the point where a retry timer would have fired again.
    #
    time.sleep(3)
    check(home.count == 1, f"home server received one packet ({home.count})")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_proxy_once():
    proxy_once("udp")


def tcp_proxy_once():
    proxy_once("tcp")


def tcp_client_once():
    proxy_once("tcp")


def udp_proxy_dup():
    """
    mode = proxy over UDP.  The NAS sends the same packet three times from the
    same source port.  The UDP listener tracks duplicates, and ignores a
    retransmit while the request is still being processed (src/lib/io/master.c).
    The module therefore does not see the duplicates, sends the packet once, and
    the final timeout does not move.
    """
    home = Home("udp")
    radiusd = start()
    sent = time.monotonic()
    nas, packet = send(1)
    time.sleep(1.5)
    send(1, packet, sock=nas)
    time.sleep(1.5)
    send(1, packet, sock=nas)

    check(radiusd.wait_for(MSG_MRD, MRD + 10), "request failed at max_rtx_duration")
    elapsed = time.monotonic() - sent
    check(MRD - 1 <= elapsed <= MRD + 3,
          f"request failed {elapsed:.1f} seconds after the first packet, max_rtx_duration is {MRD}")

    ignored = sum(1 for line in radiusd.lines if MSG_DUP_IGNORED in line)
    check(ignored == 2, f"listener ignored both duplicates ({ignored})")
    check(home.count == 1, f"home server received one packet ({home.count})")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_zombie_run():
    """
    mode = proxy over UDP with zombie_period = 8 and max_rtx_duration = 5.  The
    home server never replies.  The test sends a request at 0, 2 and 4 seconds.
    The requests fail at 5, 7 and 9 seconds.  The run of unanswered requests is
    5 and 7 seconds old at the first two failures, which is less than
    zombie_period.  At the third failure the run is 9 seconds old, so the
    connection becomes zombie.
    """
    home = Home("udp")
    radiusd = start()
    for i in range(3):
        send(i + 1)
        if i < 2:
            time.sleep(2)

    check(radiusd.wait_for(MSG_ZOMBIE, MRD + 15), "connection became zombie after a run of unanswered requests")

    #
    #  The zombie message is the third failure, and not the first or the second.
    #
    failures = [i for i, line in enumerate(radiusd.lines) if MSG_MRD in line]
    zombie = [i for i, line in enumerate(radiusd.lines) if MSG_ZOMBIE in line]
    check(len(failures) >= 3 and zombie and zombie[0] > failures[2],
          "connection became zombie at the third failure, not at the first or the second")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def zombie_failures(radiusd):
    """The indexes of the output lines where a request reached max_rtx_duration."""
    return [i for i, line in enumerate(radiusd.lines) if MSG_MRD in line]


def udp_zombie_timeouts():
    """
    mode = proxy over UDP with response_timeouts = 3, zombie_period = 8 and
    max_rtx_duration = 5.  The home server never replies.  The test sends a
    request at 0, 4 and 8 seconds.  The requests fail at 5, 9 and 13 seconds.
    At the second failure the run of unanswered requests is 9 seconds old, which
    is longer than zombie_period, but only two requests timed out.  The
    connection becomes zombie at the third failure.
    """
    home = Home("udp")
    radiusd = start()
    for i in range(3):
        send(i + 1)
        if i < 2:
            time.sleep(4)

    check(radiusd.wait_for(MSG_ZOMBIE, MRD + 15), "connection became zombie")

    failures = zombie_failures(radiusd)
    zombie = [i for i, line in enumerate(radiusd.lines) if MSG_ZOMBIE in line]
    check(len(failures) >= 3 and zombie and zombie[0] > failures[2],
          "connection became zombie at the third timeout, and not after one or two timeouts")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_zombie_reset():
    """
    mode = proxy over UDP with response_timeouts = 3, zombie_period = 8 and
    max_rtx_duration = 5.  The test sends two unanswered requests, which fail at
    5 and 9 seconds.  The home server then replies to one request at 10
    seconds, which resets the count of timeouts.  The test then sends two more
    unanswered requests, which fail at 16 and 20 seconds.  The run of unanswered
    requests is 9 seconds old at the last failure, and the count is 2 and not 4.
    The connection does not become zombie.
    """
    home = Home("udp")
    home.reply_users.add("user0003")
    radiusd = start()
    send(1)
    time.sleep(4)
    send(2)
    time.sleep(6)
    send(3)
    time.sleep(1)
    send(4)
    time.sleep(4)
    send(5)

    deadline = time.monotonic() + MRD + 10
    while len(zombie_failures(radiusd)) < 4 and time.monotonic() < deadline:
        time.sleep(0.1)

    check(len(zombie_failures(radiusd)) == 4, "four requests failed at max_rtx_duration")
    check(not radiusd.found(MSG_ZOMBIE), "a reply reset the count of timeouts, so the connection did not become zombie")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_zombie_dead():
    """
    mode = proxy over UDP with no status_check, zombie_period = 8 and
    max_rtx_duration = 5.  The home server never replies.  The test sends a
    request at 0, 2 and 4 seconds.  The connection becomes zombie at about 9
    seconds, and the test then sends no more packets.  Nothing shows that the
    home server is alive, so the zombie_period timer marks the connection dead 8
    seconds later.
    """
    home = Home("udp")
    radiusd = start()
    for i in range(3):
        send(i + 1)
        if i < 2:
            time.sleep(2)

    check(radiusd.wait_for(MSG_ZOMBIE, MRD + 15), "connection became zombie")
    check(radiusd.wait_for(MSG_DEAD, 8 + 10), "zombie_period timer marked the connection dead")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_zombie_status():
    """
    mode = proxy over UDP with status_check, num_answers_to_alive = 2,
    zombie_period = 8 and max_rtx_duration = 5.  The home server never replies to
    ordinary packets.  The home server replies to the status checks of the first
    connection, so that the connection opens, and then stops replying.  The test
    sends a request at 0, 2 and 4 seconds, and the connection becomes zombie.
    With status checks, no zombie_period timer runs, so the module does not mark
    the connection dead.  A UDP connection sends status checks in the same way as
    a TCP connection, so the module does not close the connection.  The home
    server ignores the status checks for a while, and the connection stays
    zombie.  The home server then replies, and the connection leaves the zombie
    state after two replies.
    """
    home = Home("udp")
    home.status_reply = True
    radiusd = start()
    check(radiusd.wait_for(MSG_OPEN, 30), "first connection opened after the status checks had replies")
    initial_opens = sum(1 for line in radiusd.lines if MSG_OPEN in line)
    initial_active = sum(1 for line in radiusd.lines if MSG_ACTIVE in line)
    home.status_reply = False
    home.status_times.clear()

    for i in range(3):
        send(i + 1)
        if i < 2:
            time.sleep(2)

    check(radiusd.wait_for(MSG_ZOMBIE, MRD + 15), "connection became zombie")

    #
    #  The connection sends status checks, which the home server ignores.
    #
    deadline = time.monotonic() + 15
    while not home.status_times and time.monotonic() < deadline:
        time.sleep(0.1)
    check(len(home.status_times) > 0, "module sent status checks after the connection became zombie")

    time.sleep(3)
    check(sum(1 for line in radiusd.lines if MSG_ACTIVE in line) == initial_active,
          "connection stayed zombie while the status checks had no replies")
    check(not radiusd.found(MSG_DEAD), "no zombie_period timer marked the connection dead")

    home.status_reply = True
    deadline = time.monotonic() + 15
    while sum(1 for line in radiusd.lines if MSG_ACTIVE in line) == initial_active and time.monotonic() < deadline:
        time.sleep(0.1)

    check(sum(1 for line in radiusd.lines if MSG_ACTIVE in line) == initial_active + 1,
          "connection left the zombie state after the status checks had replies")
    check(sum(1 for line in radiusd.lines if MSG_OPEN in line) == initial_opens,
          "module did not close and reopen the UDP connection")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def udp_zombie_stale():
    """
    mode = proxy over UDP with zombie_period = 8 and max_rtx_duration = 5.  The
    home server never replies.  The test sends one request at 0 seconds and one
    request at 6 seconds.  The gap is longer than max_rtx_duration, so the first
    request has already failed when the second request is written, and the
    second request starts a new run.  The second request fails at 11 seconds,
    when the new run is 5 seconds old.  The connection does not become zombie.
    """
    home = Home("udp")
    radiusd = start()
    send(1)
    time.sleep(MRD + 1)
    send(2)

    deadline = time.monotonic() + MRD + 10
    while sum(1 for line in radiusd.lines if MSG_MRD in line) < 2 and time.monotonic() < deadline:
        time.sleep(0.1)

    check(sum(1 for line in radiusd.lines if MSG_MRD in line) == 2, "both requests failed at max_rtx_duration")
    check(not radiusd.found(MSG_ZOMBIE), "a run which ended does not mark the connection zombie")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def replicate_udp():
    """
    mode = replicate over UDP.  The module sends the packet once.  A replicated
    packet has no timer, so no timeout happens after the packet is written.
    """
    home = Home("udp")
    radiusd = start()
    send(1)

    #
    #  Wait longer than max_rtx_duration, which a timer would use.
    #
    time.sleep(MRD + 3)
    check(home.count == 1, f"home server received one packet ({home.count})")
    check(not radiusd.found(MSG_MRD) and not radiusd.found(MSG_MRC), "replicated packet has no timeout")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def chap_request(ident):
    """An Access-Request with User-Name and CHAP-Password, and no CHAP-Challenge."""
    attrs = b"\x01" + bytes([2 + 8]) + b"user%04d" % ident
    attrs += bytes([CHAP_PASSWORD, 2 + 17, ident & 0xff]) + os.urandom(16)
    return struct.pack("!BBH", 1, ident & 0xff, 20 + len(attrs)) + os.urandom(16) + attrs


def tls_start(alpn):
    """Start the TLS home server, which replies to every packet, and radiusd."""
    if not os.path.exists(f"{certdir}/server.pem"):
        sys.exit(f"rlm_radius_test.py: no server certificate in {certdir}, run 'make certs'")

    home = Home("tls", reply=True, alpn=alpn)
    return home, start()


def tls_reply(sock):
    """The reply which the NAS receives, or b"" when there is no reply."""
    sock.settimeout(20)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return b""


def check_radius_1_1(home, reply):
    """The checks for a connection which negotiated radius/1.1, see RFC 9765 Sections 4 and 5."""
    check(home.selected == ALPN_RADIUS_1_1, f"home server negotiated {ALPN_RADIUS_1_1} ({home.selected})")
    check(home.count == 1, f"home server received one packet ({home.count})")
    if not home.packets:
        return

    packet = home.packets[0]
    check(packet[1] == 0, f"the ID in the header is zero ({packet[1]})")
    check(packet[8:20] == bytes(12), "the reserved octets in the header are zero")
    check(all(attr != MESSAGE_AUTHENTICATOR for attr, _ in attrs_of(packet)),
          "the packet has no Message-Authenticator")
    check(len(reply) >= 20 and reply[0] == 2, f"NAS received an Access-Accept ({len(reply)} octets)")


def check_radius_1_0(home, reply):
    """The checks for a connection which did not negotiate radius/1.1."""
    check(home.selected in (None, ALPN_RADIUS_1_0), f"home server did not negotiate {ALPN_RADIUS_1_1} ({home.selected})")
    check(home.count == 1, f"home server received one packet ({home.count})")
    if not home.packets:
        return

    #
    #  A RADIUS/1.0 Access-Request has a random Request Authenticator, where RADIUS/1.1 has zeroes after the Token.
    #
    check(home.packets[0][8:20] != bytes(12), "the Request Authenticator is not a Token and zeroes")

    #
    #  The module verifies the Response Authenticator, so a reply which the NAS received was signed correctly.
    #
    check(len(reply) >= 20 and reply[0] == 2, f"NAS received an Access-Accept ({len(reply)} octets)")


def tls_alpn_1_1():
    """
    mode = client over RADIUS/TLS with both ALPN names enabled.  The home server
    offers both names, and picks radius/1.1 because radius/1.1 is first in the
    list of the home server.  The module sends RADIUS/1.1 packets.
    """
    home, radiusd = tls_start([ALPN_RADIUS_1_1, ALPN_RADIUS_1_0])
    sock, _ = send(1)
    reply = tls_reply(sock)

    check_radius_1_1(home, reply)

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def tls_alpn_server_1_0():
    """
    mode = client over RADIUS/TLS with both ALPN names enabled.  The home server
    offers only radius/1.0, so the connection uses RADIUS/1.0.
    """
    home, radiusd = tls_start([ALPN_RADIUS_1_0])
    sock, _ = send(1)
    reply = tls_reply(sock)

    check(home.selected == ALPN_RADIUS_1_0, f"home server negotiated {ALPN_RADIUS_1_0} ({home.selected})")
    check_radius_1_0(home, reply)

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def tls_alpn_none():
    """
    mode = client over RADIUS/TLS with both ALPN names enabled.  The home server
    does not use ALPN.  radius/1.0 has the default flag, so the connection uses
    RADIUS/1.0 (RFC 9765 Section 3.3, Table 2).
    """
    home, radiusd = tls_start(None)
    sock, _ = send(1)
    reply = tls_reply(sock)

    check(home.selected is None, f"home server did not negotiate ALPN ({home.selected})")
    check_radius_1_0(home, reply)

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def tls_alpn_required():
    """
    mode = client over RADIUS/TLS with only radius/1.1 enabled.  The home server
    offers only radius/1.0, so no name is negotiated.  The client requires ALPN
    because radius/1.0 is not enabled, so the TLS connection fails and the module
    sends no packet.
    """
    home, radiusd = tls_start([ALPN_RADIUS_1_0])
    send(1)

    check(radiusd.wait_for("TLS connection failed", 20), "the TLS connection failed")
    time.sleep(1)
    check(home.count == 0, f"home server received no packet ({home.count})")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def tls_chap():
    """
    mode = client over RADIUS/TLS with both ALPN names enabled.  The NAS sends an
    Access-Request with CHAP-Password and no CHAP-Challenge.  RADIUS/1.1 has no
    Request Authenticator for the home server to use as the challenge (RFC 9765
    Section 5.1.2), so the module adds a CHAP-Challenge which is the Request
    Authenticator of the packet from the NAS.
    """
    home, radiusd = tls_start([ALPN_RADIUS_1_1, ALPN_RADIUS_1_0])
    packet = chap_request(1)
    sock, _ = send(1, packet)
    reply = tls_reply(sock)

    check_radius_1_1(home, reply)

    if home.packets:
        attrs = attrs_of(home.packets[0])
        challenge = [value for attr, value in attrs if attr == CHAP_CHALLENGE]
        check(challenge == [packet[4:20]], "the module added a CHAP-Challenge which is the Request Authenticator of the NAS")
        check(any(attr == CHAP_PASSWORD for attr, _ in attrs), "the packet has the CHAP-Password")

    radiusd.stop()
    home.close()
    finish(radiusd.lines)


def config_test(expect=(), forbid=()):
    status, out = run_config_check()
    check(status == 0, f"configuration check exited with status {status}")
    for text in expect:
        check(text in out, f"configuration check logged: {text}")
    for text in forbid:
        check(text not in out, f"configuration check did not log: {text}")

    finish(out.splitlines(keepends=True))


def config_proxy_acct_zero():
    config_test(expect=['Rewriting "Accounting-Request.max_rtx_duration = 0" to "30"'])


def config_client_acct_zero():
    config_test(forbid=["Accounting-Request.max_rtx_duration"])


def config_proxy_bounds():
    config_test(expect=['Ignoring "Access-Request.initial_rtx_time = 0.5"'])


def config_replicate_bounds():
    config_test(forbid=["Access-Request.initial_rtx_time"])


def config_zombie_period():
    config_test(expect=['Ignoring "zombie_period = 5", forcing to "zombie_period = 7.5"'])


def config_response_window():
    config_test(expect=["Ignoring 'response_window'"])


if test not in globals() or not callable(globals()[test]):
    sys.exit(f"rlm_radius_test.py: unknown test {test}")

os.makedirs(output, exist_ok=True)
for name in (f"{test}.receipt", f"{test}.log"):
    try:
        os.unlink(f"{output}/{name}")
    except FileNotFoundError:
        pass

globals()[test]()
