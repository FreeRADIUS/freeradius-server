#!/usr/bin/env python3
"""
Bidirectional Forwarding Detection (BFD) transmit intervals, detection time,
and Demand mode.

RFC 5880 Sections 6.6, 6.8.3, 6.8.4, and 6.8.7.  Because these tests wait for
real time to pass, each test uses the shortest wait that the rule allows.
"""

import unittest

from bfdlib import AbstractBfdTest, Diag, ServerConfig, State, swap32

ONE_SECOND_US = 1000000


def either_order(value: int) -> set:
    """
    Return the value of a 32-bit field in both byte orders, as a set.  Tests
    that do not check byte order call this function.  Then a byte order
    failure does not cause failures in the tests of other rules.
    """
    return {value, swap32(value)}


class StartupTransmitTest(AbstractBfdTest):
    """
    A session that is configured with a transmit interval of 100ms and is in
    state 'Down'.
    """
    CONFIG = ServerConfig(tx="100ms")

    # Known failure 1 in README.md.
    @unittest.expectedFailure
    def test_down_session_sends_no_faster_than_once_a_second(self) -> None:
        # Section 6.8.3: when the session is not Up, the transmit interval
        # is not less than one second.  Jitter takes at most 25% off it.
        first = self.peer.receive(lambda p: not p.final, 3.0)
        second = self.peer.receive(lambda p: not p.final, 3.0)

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertGreaterEqual(second.when - first.when, 0.7)

    def test_down_session_advertises_one_second(self) -> None:
        # The same rule, as seen in the field that the peer reads.
        reply = self.assertAnswered(self.packet(state=State.DOWN))

        self.assertIn(
            ONE_SECOND_US, either_order(reply.desired_min_tx),
            "Desired Min TX Interval is below one second")


class JitterTest(AbstractBfdTest):
    """
    Section 6.8.7: the server varies the time between periodic packets
    (jitter).
    """
    CONFIG = ServerConfig(tx="1s", max_timeouts=1)

    def gaps(self, count: int) -> list:
        """
        Return the gaps between the next count + 1 periodic packets, as a list
        of count values.
        """
        packets = []

        for _ in range(count + 1):
            pkt = self.peer.receive(lambda p: not p.final, 3.0)
            self.assertIsNotNone(pkt, "server stopped sending")
            packets.append(pkt)

        return [b.when - a.when for a, b in zip(packets, packets[1:])]

    def test_detect_mult_one_interval(self) -> None:
        # With Detect Mult of 1, between 75% and 90% of the interval.
        for gap in self.gaps(4):
            self.assertGreaterEqual(gap, 0.75 - 0.03)
            self.assertLessEqual(gap, 0.90 + 0.05)


class JitterMultipleTest(JitterTest):
    CONFIG = ServerConfig(tx="1s", max_timeouts=3)

    def test_detect_mult_one_interval(self) -> None:
        # With a larger Detect Mult, between 75% and 100%.
        for gap in self.gaps(4):
            self.assertGreaterEqual(gap, 0.75 - 0.03)
            self.assertLessEqual(gap, 1.00 + 0.05)


class WireFormatTest(AbstractBfdTest):
    """Intervals are 32-bit counts of microseconds, in network order."""
    CONFIG = ServerConfig(tx="1200ms", rx="250ms")

    def test_intervals_are_in_network_order(self) -> None:
        reply = self.assertAnswered(self.packet(state=State.DOWN))

        self.assertEqual(reply.required_min_rx, 250000)

        # Not 1200000: the session is not 'Up', so it sends the minimum of
        # one second.  Read in the wrong byte order, either value is far
        # above the upper bound.
        self.assertGreaterEqual(reply.desired_min_tx, 1000000)
        self.assertLessEqual(reply.desired_min_tx, 1200000)

    def test_configured_interval_is_used_once_up(self) -> None:
        # While the session is not Up the interval is at least one second.
        # The server goes back to the configured value once the session is
        # Up.  The change starts a Poll Sequence, and the server holds an
        # increase until the Poll Sequence ends (see bfd_stop_poll()), so the
        # peer ends it with a Final.
        up = self.bring_up()
        self.send(self.packet(state=State.UP, your_disc=up.my_disc,
                              final=True))

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc))
        self.assertIn(1200000, either_order(reply.desired_min_tx))


class DetectionTimeTest(AbstractBfdTest):
    """
    Section 6.8.4: in Asynchronous mode the detection time is the Detect
    Mult of the remote system, times the greater of the local Required Min
    RX Interval and the Desired Min TX Interval last received.

    The peer sends an interval of 100ms and a Detect Mult of 5.  Because of
    these values, the detection time is 500ms.  The server is configured with
    a Detect Mult of 2.  If the server used its own Detect Mult, the detection
    time would be 200ms.
    """
    CONFIG = ServerConfig(rx="100ms", max_timeouts=2)

    FIELDS = {"desired_min_tx": 100000, "required_min_rx": 100000,
              "detect_mult": 5}

    # Known failure 2 in README.md: the server uses its own Detect Mult.
    @unittest.expectedFailure
    def test_session_stays_up_until_detection_time(self) -> None:
        up = self.bring_up(**self.FIELDS)

        # Nothing sent for 350ms: less than 500ms, more than 200ms.
        self.peer.receive(lambda p: False, 0.35)

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc, **self.FIELDS))
        self.assertEqual(reply.state, State.UP,
                         "session went Down before the detection time")

    def test_session_goes_down_after_detection_time(self) -> None:
        up = self.bring_up(**self.FIELDS)

        # Nothing sent for 1.2s: more than 500ms, with room for timers.
        self.peer.receive(lambda p: False, 1.2)

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc, **self.FIELDS))
        self.assertEqual(reply.state, State.DOWN)
        self.assertEqual(reply.diag, Diag.CONTROL_EXPIRED)


class DemandModeTest(AbstractBfdTest):
    """Section 6.6: Demand mode."""
    CONFIG = ServerConfig(demand=True)

    def test_demand_bit_is_set_when_both_up(self) -> None:
        up = self.bring_up()

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc))
        self.assertTrue(reply.demand, "the D bit is not set")

    def test_demand_bit_is_clear_before_up(self) -> None:
        reply = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertFalse(reply.demand)

    def test_periodic_packets_stop_when_both_up(self) -> None:
        up = self.bring_up()
        self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc))

        self.peer.drain()

        # The interval is one second, so 1.4s is enough to see a packet.
        pkt = self.peer.receive(lambda p: not p.final, 1.4)
        self.assertIsNone(pkt, "server kept sending in Demand mode")


class RemoteDemandModeTest(AbstractBfdTest):
    """Section 6.6, when the peer asks for Demand mode."""

    def test_periodic_packets_continue_without_demand(self) -> None:
        up = self.bring_up()
        self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc))

        self.peer.drain()

        pkt = self.peer.receive(lambda p: not p.final, 2.0)
        self.assertIsNotNone(pkt, "server stopped sending")

    def test_periodic_packets_stop_when_peer_demands(self) -> None:
        up = self.bring_up()
        self.assertAnswered(self.packet(
            state=State.UP, your_disc=up.my_disc, demand=True))

        self.peer.drain()

        pkt = self.peer.receive(lambda p: not p.final, 1.4)
        self.assertIsNone(pkt, "server kept sending to a peer in Demand mode")


if __name__ == "__main__":
    unittest.main()
