#!/usr/bin/env python3
#
#  Check that the `radius` module pauses and resumes a RADIUS/TLS or a
#  RADIUS/TCP connection when the connection blocks on write.
#
#  The test starts a home server which accepts one connection and then
#  stops reading, see rlm_radius_blocked_server.py.  The test then starts
#  radiusd, waits until the radius module reports an open connection, and
#  sends 1500 large Access-Request packets to the UDP listener of radiusd.  The
#  radius module proxies the packets to the home server.  The kernel buffers
#  between the two processes fill up, and the write blocks.
#
#  The test then checks, in order:
#
#    1. radiusd logs "Writing is blocked", which is the `write_blocked`
#       callback pausing the trunk connection.
#    2. The test sends SIGUSR1 to the home server, which reads everything.
#       radiusd logs "Writing is resumed", which is the `write_resume`
#       callback resuming the trunk connection.
#    3. radiusd does not log an assertion or a signal, and exits with status
#       zero after SIGTERM.
#    4. The home server read the data, and the connection stayed valid, as
#       OpenSSL on the home server would report a damaged record.
#
#  The test waits for lines of the radiusd output, and for the exit of the
#  child processes.  The timeouts only limit how long a failing test runs.
#
#  Environment:
#    TRANSPORT "tls" (the default) or "tcp".  The test name, and so the
#              configuration file and the log files, are rlm_radius_blocked
#              for TLS and rlm_radius_blocked_tcp for TCP.
#    RADIUSD   command which runs radiusd, possibly several words
#    OUTPUT    directory for the log files
#    CONFDIR   directory holding the configuration file and the server
#    CERTDIR   directory holding the test certificates
#    DICT_PATH dictionary directory
#    PORT      port of the home server
#    LPORT     UDP port where radiusd listens
#
#  Exit status is zero when every check passes.
#
#  $Id$
#
import os
import shlex
import signal
import socket
import struct
import subprocess
import sys
import threading

radiusd = shlex.split(os.environ["RADIUSD"])
output = os.environ["OUTPUT"]
confdir = os.environ["CONFDIR"]
certdir = os.environ["CERTDIR"]
dict_path = os.environ["DICT_PATH"]
port = os.environ["PORT"]
lport = os.environ["LPORT"]

transport = os.environ.get("TRANSPORT", "tls")
if transport not in ("tls", "tcp"):
    sys.exit(f"rlm_radius_blocked.py: unknown TRANSPORT {transport}")

name = "rlm_radius_blocked" + ("_tcp" if transport == "tcp" else "")

NUM_PACKETS = 1500

#
#  A packet of 20 bytes of header, one User-Name of 8 bytes, and 14
#  Reply-Message attributes of 240 bytes, is 3418 bytes.  The radius module
#  adds about 28 more bytes.
#
PACKET_BODY = 14

#
#  The lines of the radiusd output, and one event for each line which the test
#  waits for.  The events are all set when radiusd closes the output, so that
#  a radiusd which exits early does not leave the test waiting.
#
lines = []
marks = {
    "open": "TLS connection open" if transport == "tls" else "Connection open",
    "blocked": "Writing is blocked",
    "resumed": "Writing is resumed",
}
events = {name: threading.Event() for name in marks}
failed = []


def check(ok, message):
    print(("ok: " if ok else "FAILED: ") + message, flush=True)
    if not ok:
        failed.append(message)
    return ok


def found(name):
    return any(marks[name] in line for line in lines)


def wait(name, timeout):
    events[name].wait(timeout)
    return found(name)


def finish():
    with open(f"{output}/{name}_radiusd.log", "w") as f:
        f.writelines(lines)

    if failed:
        print(f"{name}: failed: " + "; ".join(failed))
        sys.exit(1)

    sys.exit(0)


server = subprocess.Popen([sys.executable, "-I", f"{confdir}/rlm_radius_blocked_server.py", port, certdir] +
                          (["tcp"] if transport == "tcp" else []),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

if not check(server.stdout.readline().strip() == "listening", "home server is listening"):
    finish()

env = dict(os.environ, PORT=port, LPORT=lport)
rad = subprocess.Popen(radiusd + ["-d", confdir, "-D", dict_path, "-n", name,
                                  "-msx", "-e", "60", "-l", "stdout"],
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def reader():
    for line in rad.stdout:
        lines.append(line)
        for name, text in marks.items():
            if text in line:
                events[name].set()

    for event in events.values():
        event.set()


reader_thread = threading.Thread(target=reader, daemon=True)
reader_thread.start()

if check(wait("open", 30), f"radius module opened the {transport.upper()} connection"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(NUM_PACKETS):
        attrs = b"\x01" + bytes([2 + 8]) + b"user%04d" % i
        for _ in range(PACKET_BODY):
            attrs += b"\x12" + bytes([2 + 240]) + b"x" * 240

        packet = struct.pack("!BBH", 1, i & 0xff, 20 + len(attrs)) + os.urandom(16) + attrs
        sock.sendto(packet, ("127.0.0.1", int(lport)))

    if check(wait("blocked", 30), "radius module paused the connection when the write blocked"):
        #
        #  The home server reads, which lets the radius module write the rest of the data.
        #
        server.send_signal(signal.SIGUSR1)
        check(wait("resumed", 30), "radius module resumed the connection after the write unblocked")

rad.send_signal(signal.SIGTERM)
try:
    rad.wait(30)
except subprocess.TimeoutExpired:
    rad.kill()
    rad.wait()
    failed.append("radiusd did not exit after SIGTERM")

#
#  radiusd closed the output when radiusd exited, so the reader has every line once the reader ends.
#
reader_thread.join()

check(not any(("ASSERT FAILED" in line) or ("CAUGHT SIGNAL" in line) for line in lines),
      "radiusd logged no assertion or signal")
check(rad.returncode == 0, f"radiusd exited with status {rad.returncode}")

#
#  The home server prints "handshake done" (TLS) or "connected" (TCP) first, and then the number of bytes when the radius module
#  closes the connection.
#
#
#  The home server waits for SIGUSR1 before reading.  The test did not send SIGUSR1 when a check failed
#  earlier, so send SIGUSR1 again here, as a server which still waits would never end.
#
server.send_signal(signal.SIGUSR1)

server_lines = []
for line in server.stdout:
    server_lines.append(line.strip())

first = "handshake done" if transport == "tls" else "connected"
check(server_lines[:1] == [first], "home server accepted the connection" if transport == "tcp"
      else "home server finished the TLS handshake")
drained = [line for line in server_lines if line.startswith("drained ")]
check(len(drained) == 1 and int(drained[0].split()[1]) > 0, "home server read the data after the pause")

#
#  Writes which blocked part way through a packet must not lose the rest of the packet.
#
framing = [line for line in server_lines if line.startswith("framing ")]
check(len(framing) == 1 and framing[0].startswith("framing ok ") and int(framing[0].split()[2]) > 0,
      "home server read whole packets: " + (framing[0] if framing else "no framing line"))
server.wait()

with open(f"{output}/{name}_server.log", "w") as f:
    f.write("\n".join(server_lines) + "\n")

finish()
