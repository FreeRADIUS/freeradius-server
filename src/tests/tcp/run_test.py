#!/usr/bin/env python3
"""Run one scenario of the plain TCP proxy tests.

The script starts a home server that listens on TCP and a radiusd which
proxies UDP requests to the home server. The script then runs the scenario
and stops both. The exit status is non-zero when the scenario fails, and zero
when the scenario passes or cannot be set up on this platform.

The script does not call time.sleep(). The script waits for a line in the
output of radiusd, for a threading.Event, or for a socket timeout.
"""
import argparse
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading

from client import RadiusClient
from home_server import HomeServer

SECRET = b'testing123'
READY = "Ready to process requests"

# The number and the size of the requests in the stall scenario. The requests
# add up to more than a socket send buffer of 128K, which is the default on
# macOS. The requests add up to less than 128K plus the write buffer of
# 64K, so that the proxy does not drop any request.
STALL_REQUESTS = 40
STALL_PADDING = 15


class TestFailure(Exception):
    """The scenario did not behave as expected."""


class TestSkipped(Exception):
    """The platform cannot set up the scenario."""


class Radiusd:
    """A radiusd process, and the lines that the process writes."""

    def __init__(self, command: str, dictdir: str, conf_dir: str,
                 env: dict[str, str], log_path: str):
        self.log_path = log_path

        words = shlex.split(command)
        self._env = dict(os.environ, **env)
        while words and '=' in words[0]:
            name, value = words.pop(0).split('=', 1)
            self._env[name] = value

        self._args = words + ['-X', '-d', conf_dir, '-D', dictdir]

        self._proc: subprocess.Popen = None
        self._lines: list[str] = []
        self._cond = threading.Condition()

    def start(self, timeout: float) -> None:
        """Start radiusd and wait until radiusd is ready for requests."""
        self._proc = subprocess.Popen(self._args, env=self._env,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True,
                                      start_new_session=True)
        threading.Thread(target=self._read, daemon=True).start()

        if not self.wait_for(re.escape(READY), timeout):
            raise TestFailure("radiusd did not become ready")

    def alive(self) -> bool:
        return self._proc.poll() is None

    def wait_for(self, pattern: str, timeout: float, count: int = 1) -> bool:
        """Wait until count lines match the regular expression."""
        regex = re.compile(pattern)

        def enough() -> bool:
            matches = sum(1 for line in self._lines if regex.search(line))
            return matches >= count or self._proc.poll() is not None

        with self._cond:
            self._cond.wait_for(enough, timeout)
            return sum(1 for line in self._lines if regex.search(line)) >= count

    def tail(self, count: int = 40) -> str:
        with self._cond:
            return ''.join(self._lines[-count:])

    def stop(self) -> None:
        """Stop radiusd and all of the processes that radiusd started."""
        if self._proc is None:
            return

        if self.alive():
            os.killpg(self._proc.pid, signal.SIGTERM)

        try:
            self._proc.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(self._proc.pid, signal.SIGKILL)
            self._proc.wait()

    def _read(self) -> None:
        with open(self.log_path, 'w', encoding='utf-8') as log:
            for line in self._proc.stdout:
                log.write(line)
                with self._cond:
                    self._lines.append(line)
                    self._cond.notify_all()

        with self._cond:
            self._cond.notify_all()


def free_udp_port() -> int:
    """Find a UDP port that nothing uses."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def scenario_reply(home: HomeServer, radiusd: Radiusd, port: int) -> None:
    """The proxy gets a reply from the home server over TCP."""
    with RadiusClient(port, SECRET) as client:
        for identifier in range(3):
            reply = client.exchange(identifier, 5)
            require(reply is not None,
                    f"No reply to request {identifier}")

    require(home.requests == 3,
            f"Home server saw {home.requests} requests, expected 3")


def scenario_refuse(home: HomeServer, radiusd: Radiusd, port: int) -> None:
    """The home server refuses the connection, and radiusd stays up."""
    with RadiusClient(port, SECRET) as client:
        require(client.exchange(1, 3) is None,
                "Got a reply from a home server that refuses connections")

    require(radiusd.wait_for("Failed connecting to home server", 5),
            "radiusd did not log the failed connection")
    require(radiusd.alive(), "radiusd exited")


def scenario_close(home: HomeServer, radiusd: Radiusd, port: int) -> None:
    """The home server closes the connection, and radiusd stays up."""
    with RadiusClient(port, SECRET) as client:
        require(client.exchange(1, 3) is None,
                "Got a reply from a home server that closes connections")

    require(home.accepted.is_set(), "Home server did not accept")
    require(radiusd.wait_for("closed connection|Error (reading|writing)", 5),
            "radiusd did not log the closed connection")
    require(radiusd.alive(), "radiusd exited")


def scenario_stall(home: HomeServer, radiusd: Radiusd, port: int) -> None:
    """The home server does not read, then reads, and no request is lost."""
    identifiers = set(range(STALL_REQUESTS))

    with RadiusClient(port, SECRET) as client:
        for identifier in identifiers:
            client.send(identifier, STALL_PADDING)

        require(home.accepted.wait(10), "Home server did not accept")
        require(radiusd.wait_for("Sent Access-Request Id", 10,
                                 STALL_REQUESTS),
                "radiusd did not send all of the requests")

        home.release()

        missing = client.collect(identifiers, 10)
        require(not missing, f"No reply to requests {sorted(missing)}")

    require(radiusd.alive(), "radiusd exited")


def scenario_slow_accept(home: HomeServer, radiusd: Radiusd,
                         port: int) -> None:
    """The connect() stays pending until the home server accepts."""
    if not home.backlog_full:
        raise TestSkipped("Cannot fill the listen backlog on this platform")

    with RadiusClient(port, SECRET) as client:
        client.send(1)

        require(radiusd.wait_for("Listening on proxy .* -> home_server", 10),
                "radiusd did not open a proxy socket")
        home.release()

        reply = client.receive(25)
        require(reply is not None,
                "No reply after the home server started to accept")

    require(radiusd.alive(), "radiusd exited")


SCENARIOS = {
    'reply': scenario_reply,
    'refuse': scenario_refuse,
    'close': scenario_close,
    'stall': scenario_stall,
    'slow-accept': scenario_slow_accept,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=sorted(SCENARIOS))
    parser.add_argument('--radiusd', required=True,
                        help="command that runs radiusd")
    parser.add_argument('--dictdir', required=True)
    parser.add_argument('--conf-dir', required=True)
    parser.add_argument('--out-dir', required=True)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    home = HomeServer(args.scenario, SECRET)
    proxy_port = free_udp_port()
    radiusd = None

    try:
        home.start()

        env = {'TEST_DIR': os.path.abspath(args.out_dir),
               'TEST_PROXY_PORT': str(proxy_port),
               'TEST_HOME_PORT': str(home.port)}
        radiusd = Radiusd(args.radiusd, args.dictdir, args.conf_dir, env,
                          os.path.join(args.out_dir, 'radiusd.log'))
        radiusd.start(30)

        SCENARIOS[args.scenario](home, radiusd, proxy_port)

    except TestSkipped as exc:
        print(f"SKIP {args.scenario}: {exc}")
        return 0

    except (TestFailure, ValueError) as exc:
        print(f"FAIL {args.scenario}: {exc}")
        if radiusd:
            print(f"Last lines of {radiusd.log_path}:")
            print(radiusd.tail())
        return 1

    finally:
        if radiusd:
            radiusd.stop()
        home.stop()

    print(f"PASS {args.scenario}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
