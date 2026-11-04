"""A UDP RADIUS client that sends requests to the proxy."""
import socket

import radius


class RadiusClient:
    """Sends Access-Requests to the proxy and checks the replies."""

    def __init__(self, port: int, secret: bytes):
        self.port = port
        self.secret = secret

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.authenticators: dict[int, bytes] = {}

    def __enter__(self) -> 'RadiusClient':
        return self

    def __exit__(self, *exc) -> None:
        self.sock.close()

    def send(self, identifier: int, padding: int = 0) -> None:
        """Send one Access-Request."""
        packet, authenticator = radius.access_request(identifier, padding)
        self.authenticators[identifier] = authenticator
        self.sock.sendto(packet, ('127.0.0.1', self.port))

    def receive(self, timeout: float) -> radius.Packet:
        """Wait for one reply. Returns None if the timeout expires.

        Raises ValueError if the reply is not an Access-Accept with a valid
        Response Authenticator.
        """
        self.sock.settimeout(timeout)

        try:
            data = self.sock.recv(radius.MAX_PACKET_LEN)
        except socket.timeout:
            return None

        packet = radius.parse(data)
        if packet.code != radius.ACCESS_ACCEPT:
            raise ValueError(f"Expected Access-Accept, got code {packet.code}")

        authenticator = self.authenticators.get(packet.identifier)
        if authenticator is None:
            raise ValueError(f"Reply has unknown ID {packet.identifier}")

        if not radius.response_valid(data, authenticator, self.secret):
            raise ValueError(f"Reply ID {packet.identifier} has an invalid "
                             "Response Authenticator")

        return packet

    def exchange(self, identifier: int, timeout: float) -> radius.Packet:
        """Send one request and wait for the reply. None means no reply."""
        self.send(identifier)

        return self.receive(timeout)

    def collect(self, identifiers: set[int], timeout: float) -> set[int]:
        """Wait for replies. Returns the IDs that did not get a reply."""
        missing = set(identifiers)

        while missing:
            packet = self.receive(timeout)
            if packet is None:
                break

            missing.discard(packet.identifier)

        return missing
