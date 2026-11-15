#!/usr/bin/env python3
"""
BFD authentication.

RFC 5880 Section 6.7 defines five authentication types: simple password,
keyed Message Digest 5 (MD5), meticulous keyed MD5, keyed Secure Hash
Algorithm 1 (SHA1), and meticulous keyed SHA1.  A keyed type has a sequence
number that may advance occasionally.  A meticulous type has a sequence number
that must advance on every packet.

The same tests run for every type.  `BaseAuthTests` holds the tests that apply
to every type.  `BaseDigestTests` holds the tests that need a sequence number.
The leaf classes at the end choose the type.
"""

import unittest

from bfdlib import (AbstractBfdTest, AuthType, BfdPacket, HEADER_LEN,
                    ServerConfig, State)


class BaseAuthTests:
    """
    Tests for every authentication type.  Mix this class into a test class.
    """

    def test_signed_packet_is_answered(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))

    def test_answer_is_authenticated(self) -> None:
        reply = self.assertAnswered(self.packet(state=State.DOWN))

        self.assertTrue(reply.auth_present, "the A bit is not set")
        self.assertEqual(reply.auth_type, self.CONFIG.auth_type)
        self.assertEqual(reply.length, HEADER_LEN + reply.auth_len)

    def test_unsigned_packet_is_discarded(self) -> None:
        # Section 6.8.6: the A bit is clear, and authentication is in use.
        self.assertDiscarded(self.packet(state=State.DOWN, auth_type=None))

    def test_wrong_secret_is_discarded(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))

        pkt = self.packet(state=State.DOWN, poll=True)

        if self.CONFIG.auth_type == AuthType.SIMPLE:
            pkt.password = b"wrong-password"
            raw = pkt.pack()
        else:
            raw = pkt.pack(b"wrong-secret")

        self.peer.send(raw, self.server.listen_port)
        self.assertIsNone(self.peer.receive(lambda p: p.final, 0.3))

    def test_other_key_id_is_discarded(self) -> None:
        # Only one key is configured, so no other Key ID can match it.
        self.assertDiscarded(self.packet(state=State.DOWN, key_id=1))

    def assertTypeMismatchDiscarded(self, other: AuthType) -> None:
        """
        A packet which is correctly signed, but with another type than the
        session uses.  It is sent first: for a digest type the first packet
        is accepted whatever its sequence number, so that only the type
        can make the server discard it.
        """
        pkt = self.packet(state=State.DOWN, auth_type=other,
                          password=self.secret)
        self.assertIsNone(self.probe(pkt),
                          f"a {other.name} packet was accepted by a "
                          f"{self.CONFIG.auth_type.name} session")

        self.assertAnswered(self.packet(state=State.DOWN))

    def test_auth_length_mismatch_is_discarded(self) -> None:
        # Auth Len must agree with the Length of the packet.
        self.assertDiscarded(self.packet(state=State.DOWN, auth_len=3 + 2))

    def test_state_machine_works_with_auth(self) -> None:
        up = self.bring_up()
        self.assertEqual(up.state, State.UP)


class BaseDigestTests(BaseAuthTests):
    """Extra tests for the authentication types that have a sequence number."""

    # Meticulous types must advance on every packet.
    METICULOUS = False

    def test_digest_of_answer_is_correct(self) -> None:
        reply = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertTrue(BfdPacket.digest_ok(reply.raw, self.secret),
                        "the digest of the answer does not verify")

    def test_first_sequence_is_accepted_whatever_it_is(self) -> None:
        # Section 6.7.3: until a sequence number is known, any is taken.
        self.assertAnswered(self.packet(state=State.DOWN,
                                        sequence=0xdeadbeef))

    def test_consecutive_sequence_is_accepted(self) -> None:
        for _ in range(4):
            self.assertAnswered(self.packet(state=State.DOWN))

    def test_sequence_wraps(self) -> None:
        for sequence in (0xfffffffe, 0xffffffff, 0, 1):
            with self.subTest(sequence=sequence):
                self.assertAnswered(self.packet(state=State.DOWN,
                                                sequence=sequence))

    def test_old_sequence_is_discarded(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN, sequence=5000))
        self.assertAnswered(self.packet(state=State.DOWN, sequence=5001))

        pkt = self.packet(state=State.DOWN, sequence=4990, poll=True)
        self.send(pkt)
        self.assertIsNone(self.peer.receive(lambda p: p.final, 0.3))

    def test_far_future_sequence_is_discarded(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN, sequence=5000))

        pkt = self.packet(state=State.DOWN, sequence=5000 + 100000,
                          poll=True)
        self.send(pkt)
        self.assertIsNone(self.peer.receive(lambda p: p.final, 0.3))

    def test_repeated_sequence(self) -> None:
        # Keyed: the same number again is in the window.  Meticulous: the
        # number must be greater than the last one.
        self.assertAnswered(self.packet(state=State.DOWN, sequence=7000))

        pkt = self.packet(state=State.DOWN, sequence=7000, poll=True)
        self.send(pkt)
        reply = self.peer.receive(lambda p: p.final, 0.3)

        if self.METICULOUS:
            self.assertIsNone(reply, "a repeated sequence was accepted")
        else:
            self.assertIsNotNone(reply, "a repeated sequence was refused")

    def test_sequence_of_answers_advances(self) -> None:
        # Section 6.7.3: the sequence number is sent in network order.
        # The server sends a new number every time, which is what a
        # meticulous type needs, and is allowed for a keyed type.
        sequences = []

        for _ in range(3):
            reply = self.assertAnswered(self.packet(state=State.DOWN))
            sequences.append(reply.sequence)

        for earlier, later in zip(sequences, sequences[1:]):
            self.assertEqual((later - earlier) & 0xffffffff, 1,
                             f"sequence numbers are {sequences}")


def add_mismatch_tests(cls):
    """
    Add one test per authentication type other than the one configured.
    """
    for other in AuthType:
        if other == cls.CONFIG.auth_type:
            continue

        def check(self, other=other) -> None:
            self.assertTypeMismatchDiscarded(other)

        setattr(cls, f"test_{other.name.lower()}_is_discarded", check)

    return cls


@add_mismatch_tests
class SimpleAuthTest(BaseAuthTests, AbstractBfdTest):
    CONFIG = ServerConfig(auth_type=AuthType.SIMPLE, secret="s3cret")


@add_mismatch_tests
class KeyedMd5AuthTest(BaseDigestTests, AbstractBfdTest):
    CONFIG = ServerConfig(auth_type=AuthType.KEYED_MD5)


@add_mismatch_tests
class MeticulousMd5AuthTest(BaseDigestTests, AbstractBfdTest):
    CONFIG = ServerConfig(auth_type=AuthType.MET_KEYED_MD5)
    METICULOUS = True


@add_mismatch_tests
class KeyedSha1AuthTest(BaseDigestTests, AbstractBfdTest):
    CONFIG = ServerConfig(auth_type=AuthType.KEYED_SHA1)


@add_mismatch_tests
class MeticulousSha1AuthTest(BaseDigestTests, AbstractBfdTest):
    CONFIG = ServerConfig(auth_type=AuthType.MET_KEYED_SHA1)
    METICULOUS = True


if __name__ == "__main__":
    unittest.main()
