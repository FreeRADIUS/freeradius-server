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

SECRET = b"testing123"

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


def reply_to(packet):
    """An Access-Accept for the Access-Request, with a valid Response-Authenticator."""
    code, ident, length = struct.unpack("!BBH", packet[:4])
    head = struct.pack("!BBH", 2, ident, 20)
    return head + hashlib.md5(head + packet[4:20] + SECRET).digest()


class Home:
    """
    A home server over UDP or TCP, which records the time of every packet.

    The home server drops the first "drop" packets, and replies to every later
    packet when "reply" is true.
    """

    def __init__(self, transport, drop=0, reply=False):
        self.transport = transport
        self.drop = drop
        self.reply = reply
        self.times = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        if transport == "tcp":
            self.sock.listen(1)
        self.stop = False
        self.thread = threading.Thread(target=self.run_udp if transport == "udp" else self.run_tcp, daemon=True)
        self.thread.start()

    def seen(self, packet, send):
        self.times.append(time.monotonic())
        if self.reply and len(self.times) > self.drop:
            send(reply_to(packet))

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

        conn.settimeout(0.2)
        data = b""
        while not self.stop:
            try:
                more = conn.recv(4096)
            except socket.timeout:
                continue
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
        check(self.proc.returncode == 0, f"radiusd exited with status {self.proc.returncode}")


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
