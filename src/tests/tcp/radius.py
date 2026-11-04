"""Build and parse the few RADIUS packets that the TCP proxy tests need."""
import dataclasses
import hashlib
import os
import struct

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
USER_NAME = 1
CALLBACK_ID = 20
PROXY_STATE = 33

HEADER_LEN = 20
MAX_PACKET_LEN = 4096


@dataclasses.dataclass
class Packet:
    """One decoded RADIUS packet."""
    code: int
    identifier: int
    authenticator: bytes
    attributes: list[tuple[int, bytes]]


def encode(code: int, identifier: int, authenticator: bytes,
           attributes: list[tuple[int, bytes]]) -> bytes:
    """Encode a packet from its fields."""
    body = b''.join(struct.pack('!BB', attrtype, len(value) + 2) + value
                    for attrtype, value in attributes)

    return (struct.pack('!BBH', code, identifier, HEADER_LEN + len(body)) +
            authenticator + body)


def parse(data: bytes) -> Packet:
    """Decode a whole packet. Raises ValueError if the packet is malformed."""
    if len(data) < HEADER_LEN:
        raise ValueError("Packet is shorter than the RADIUS header")

    code, identifier, length = struct.unpack('!BBH', data[:4])
    if length != len(data):
        raise ValueError(f"Header length {length} does not match the "
                         f"{len(data)} bytes received")

    attributes = []
    offset = HEADER_LEN
    while offset < length:
        if offset + 2 > length or data[offset + 1] < 2:
            raise ValueError("Malformed attribute")

        attrlen = data[offset + 1]
        if offset + attrlen > length:
            raise ValueError("Attribute runs past the end of the packet")

        attributes.append((data[offset], data[offset + 2:offset + attrlen]))
        offset += attrlen

    return Packet(code, identifier, data[4:HEADER_LEN], attributes)


def access_request(identifier: int, padding: int = 0) -> tuple[bytes, bytes]:
    """Build an Access-Request. Returns the packet and its authenticator.

    Each unit of padding adds a 253 byte Callback-Id attribute, so that a test
    can make the request large.
    """
    authenticator = os.urandom(16)
    attributes = [(USER_NAME, b'bob')]
    attributes += [(CALLBACK_ID, b'x' * 253)] * padding

    return (encode(ACCESS_REQUEST, identifier, authenticator, attributes),
            authenticator)


def access_accept(request: Packet, secret: bytes) -> bytes:
    """Build the Access-Accept for a request.

    The reply carries the Proxy-State attributes of the request, because the
    proxy uses Proxy-State to match the reply.
    """
    attributes = [(attrtype, value) for attrtype, value in request.attributes
                  if attrtype == PROXY_STATE]
    packet = encode(ACCESS_ACCEPT, request.identifier,
                    request.authenticator, attributes)

    # The Response Authenticator hashes the packet, which holds the request
    # authenticator in the authenticator field, followed by the secret.
    digest = hashlib.md5(packet + secret).digest()

    return packet[:4] + digest + packet[HEADER_LEN:]


def response_valid(response: bytes, request_authenticator: bytes,
                   secret: bytes) -> bool:
    """Check the Response Authenticator of a reply."""
    digest = hashlib.md5(response[:4] + request_authenticator +
                         response[HEADER_LEN:] + secret).digest()

    return digest == response[4:HEADER_LEN]


def split(buffer: bytearray) -> list[bytes]:
    """Remove the whole packets from the front of a TCP stream buffer.

    Raises ValueError if a length field is outside of the RADIUS limits.
    """
    packets = []

    while len(buffer) >= 4:
        length = struct.unpack('!H', buffer[2:4])[0]
        if length < HEADER_LEN or length > MAX_PACKET_LEN:
            raise ValueError(f"Invalid packet length {length}")

        if len(buffer) < length:
            break

        packets.append(bytes(buffer[:length]))
        del buffer[:length]

    return packets
