#!/usr/bin/env python3
"""
Packet validation by the Bidirectional Forwarding Detection (BFD) listener.

RFC 5880 Section 6.8.6 lists the checks that a received BFD Control packet
must pass.  The server discards a packet that fails any of the checks.  A test
detects the discard when the server does not answer a packet with the Poll bit
set.

Before sending a bad packet, each negative test checks that the server answers
a good packet.  Then silence means that the server discarded the bad packet,
and not that the server was not listening.
"""

import unittest

from bfdlib import AbstractBfdTest, AuthType, HEADER_LEN, State


class PacketValidationTest(AbstractBfdTest):
    """Checks on a session which uses no authentication."""

    def test_good_packet_is_answered(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))

    def test_answer_fields(self) -> None:
        # Section 6.8.7: the fields of a packet which the server sends.
        reply = self.assertAnswered(self.packet(state=State.DOWN))

        self.assertEqual(reply.version, 1)
        self.assertEqual(reply.length, HEADER_LEN)
        self.assertEqual(reply.detect_mult, self.CONFIG.max_timeouts)
        self.assertNotEqual(reply.my_disc, 0)
        self.assertEqual(reply.your_disc, self.disc,
                         "Your Discriminator is not the peer's discriminator")
        self.assertTrue(reply.final)
        self.assertFalse(reply.poll)
        self.assertFalse(reply.multipoint)
        self.assertFalse(reply.auth_present)
        self.assertFalse(reply.demand)
        self.assertEqual(reply.echo_rx, 0,
                         "Required Min Echo RX Interval must be zero when "
                         "echo is not supported")

    def test_wrong_version_is_discarded(self) -> None:
        for version in (0, 2, 7):
            with self.subTest(version=version):
                self.assertDiscarded(self.packet(version=version))

    def test_zero_detect_mult_is_discarded(self) -> None:
        self.assertDiscarded(self.packet(detect_mult=0))

    def test_length_below_minimum_is_discarded(self) -> None:
        for length in (0, 12, 23):
            with self.subTest(length=length):
                self.assertDiscarded(self.packet(length=length))

    def test_length_beyond_payload_is_discarded(self) -> None:
        for length in (25, 64, 255):
            with self.subTest(length=length):
                self.assertDiscarded(self.packet(length=length))

    def test_truncated_datagram_is_discarded(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))

        pkt = self.packet(state=State.DOWN, poll=True)

        for size in (0, 1, 8, 23):
            with self.subTest(size=size):
                self.peer.send(pkt.pack()[:size], self.server.listen_port)
                reply = self.peer.receive(lambda p: p.final, 0.3)
                self.assertIsNone(reply)

    def test_multipoint_is_discarded(self) -> None:
        self.assertDiscarded(self.packet(multipoint=True))

    def test_zero_my_discriminator_is_discarded(self) -> None:
        self.assertDiscarded(self.packet(my_disc=0))

    def test_zero_your_discriminator_is_discarded_unless_down(self) -> None:
        # Section 6.8.6: Your Discriminator may be zero only when the
        # State is Down or AdminDown.
        for state in (State.INIT, State.UP):
            with self.subTest(state=state.name):
                self.assertDiscarded(self.packet(state=state, your_disc=0))

    def test_zero_your_discriminator_is_accepted_when_down(self) -> None:
        for state in (State.DOWN, State.ADMIN_DOWN):
            with self.subTest(state=state.name):
                self.assertAnswered(self.packet(state=state, your_disc=0))

    def test_unknown_your_discriminator_is_discarded(self) -> None:
        # The first answer tells us the server discriminator, so that we
        # can then send one which is certainly not it.
        reply = self.assertAnswered(self.packet(state=State.DOWN))

        wrong = reply.my_disc ^ 0x00ff00ff
        self.assertDiscarded(self.packet(state=State.INIT, your_disc=wrong))

    def test_auth_bit_without_authentication_is_discarded(self) -> None:
        # Section 6.8.6: the A bit is set, and no authentication is in use.
        self.assertDiscarded(self.packet(auth_type=AuthType.SIMPLE,
                                         password=b"secret"))

    def test_auth_bit_without_auth_section_is_discarded(self) -> None:
        # The A bit is set but the packet ends after 24 octets.
        self.assertDiscarded(self.packet(auth_present=True))

    def test_garbage_datagram_is_ignored(self) -> None:
        # A datagram which is not BFD at all.  The server must not stop
        # working because of it.
        self.peer.send(b"not a BFD packet at all, just text",
                       self.server.listen_port)
        self.assertAnswered(self.packet(state=State.DOWN))


if __name__ == "__main__":
    unittest.main()
