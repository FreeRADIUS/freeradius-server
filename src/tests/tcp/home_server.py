"""A Remote Authentication Dial-In User Service (RADIUS) home server.

The home server listens on TCP, with one mode per scenario.
"""
import select
import socket
import threading

import radius

MODES = ('reply', 'refuse', 'close', 'stall', 'slow-accept')

# In the stall mode, the home server shrinks the receive buffer to STALL_RCVBUF
# bytes. The proxy then needs less data to fill the send buffer of the proxy
# socket and the receive buffer of the home server.
STALL_RCVBUF = 4096

# MAX_FILLERS is the most connections that slow-accept opens to fill the listen
# backlog. macOS accepts kern.ipc.somaxconn (128) connections even when the
# program calls listen(0). Because of that, MAX_FILLERS must exceed 128.
# MAX_FILLERS must also stay below the default limit of 256 open files on
# macOS.
MAX_FILLERS = 200


class HomeServer:
    """A TCP home server.

    The mode decides what the server does with a connection:

    reply        answers each request with an Access-Accept.
    refuse       does not listen. The proxy receives a connection refusal.
    close        accepts a connection and closes the connection.
    stall        accepts a connection but does not read until release().
    slow-accept  fills the listen backlog and does not accept a connection until
                 release(). Because the backlog is full, a connect() from the
                 proxy stays pending.
    """

    def __init__(self, mode: str, secret: bytes):
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode}")

        self.mode = mode
        self.secret = secret

        self.port: int = 0
        self.accepted = threading.Event()
        self.requests: int = 0
        self.backlog_full: bool = False

        self._listener: socket.socket = None
        self._fillers: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._released = threading.Event()
        self._stopping = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> None:
        """Bind a TCP socket on 127.0.0.1 and set `port`.

        Start the accept loop in every mode except refuse and slow-accept.
        """
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.mode == 'stall':
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                      STALL_RCVBUF)

        self._listener.bind(('127.0.0.1', 0))
        self.port = self._listener.getsockname()[1]

        match self.mode:
            case 'refuse':
                # Because nothing listens on the port, connect() is refused.
                self._listener.close()
                self._listener = None

            case 'slow-accept':
                self._listener.listen(0)
                self._fill_backlog()

            case _:
                self._listener.listen(8)
                self._spawn(self._accept_loop)

    def release(self) -> None:
        """Make the home server start to read (stall mode) or to accept connections
        (slow-accept mode).
        """
        self._released.set()

        if self.mode == 'slow-accept':
            self._spawn(self._accept_loop)

    def stop(self) -> None:
        """Stop all of the threads and close all of the sockets."""
        self._stopping.set()
        self._released.set()

        for thread in self._threads:
            thread.join(5)

        for sock in self._fillers + [self._listener]:
            if sock:
                sock.close()

    def _spawn(self, target, *args) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True)
        self._threads.append(thread)
        thread.start()

    def _fill_backlog(self) -> None:
        """Open connections until a connect() cannot finish.

        A connect() that does not finish within the select() timeout means
        that the backlog is full. The pending connect() stays open, so that the backlog
        stays full until the accept loop starts.
        """
        for _ in range(MAX_FILLERS):
            filler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            filler.setblocking(False)
            filler.connect_ex(('127.0.0.1', self.port))
            self._fillers.append(filler)

            _, writable, _ = select.select([], [filler], [], 0.2)
            if not writable:
                self.backlog_full = True
                return

    def _accept_loop(self) -> None:
        self._listener.settimeout(0.2)

        while not self._stopping.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            self.accepted.set()
            self._spawn(self._serve, conn)

    def _serve(self, conn: socket.socket) -> None:
        """Answer the requests on one connection."""
        if self.mode == 'close':
            conn.close()
            return

        if self.mode == 'stall':
            while not self._released.wait(0.2):
                if self._stopping.is_set():
                    conn.close()
                    return

        buffer = bytearray()
        conn.settimeout(0.2)

        while not self._stopping.is_set():
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break

            if not data:
                break

            buffer += data
            for raw in radius.split(buffer):
                with self._lock:
                    self.requests += 1

                conn.sendall(radius.access_accept(radius.parse(raw),
                                                  self.secret))

        conn.close()
