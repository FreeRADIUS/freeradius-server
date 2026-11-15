#!/usr/bin/env python3
"""
The BFD session state machine.

RFC 5880 Section 6.8.6 gives the state changes that follow from the State
field of a received packet.  The tests drive the server session through the
state changes.  Each test sends a packet with the Poll bit set to read the
state of the session at once.
"""

import unittest

from bfdlib import AbstractBfdTest, Diag, HEADER_LEN, State


class SessionStateTest(AbstractBfdTest):
    """State changes on a session which uses no authentication."""

    def test_first_periodic_packet(self) -> None:
        # Section 6.8.7: a session starts Down, and with no Your
        # Discriminator the server is the Active side, which sends
        # without waiting to be spoken to.
        pkt = self.peer.receive(lambda p: not p.final, 3.0)
        self.assertIsNotNone(pkt, "server sent no periodic packet")

        self.assertEqual(pkt.version, 1)
        self.assertEqual(pkt.state, State.DOWN)
        self.assertEqual(pkt.diag, Diag.NONE)
        self.assertEqual(pkt.your_disc, 0)
        self.assertNotEqual(pkt.my_disc, 0)
        self.assertEqual(pkt.length, HEADER_LEN)
        self.assertEqual(pkt.detect_mult, self.CONFIG.max_timeouts)
        self.assertFalse(pkt.poll)
        self.assertFalse(pkt.final)
        self.assertFalse(pkt.demand)
        self.assertFalse(pkt.multipoint)
        self.assertFalse(pkt.auth_present)

    def test_down_to_init_to_up(self) -> None:
        down = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(down.state, State.INIT, "Down + Down is not Init")

        up = self.assertAnswered(self.packet(
            state=State.INIT, your_disc=down.my_disc))
        self.assertEqual(up.state, State.UP, "Init + Init is not Up")
        self.assertEqual(up.my_disc, down.my_disc,
                         "the server discriminator changed")
        self.assertEqual(up.your_disc, self.disc)

    def test_down_to_up_when_peer_is_init(self) -> None:
        # Section 6.8.6: Down, and the peer says Init, is Up.
        sd = self.server_disc()

        reply = self.assertAnswered(self.packet(
            state=State.INIT, your_disc=sd))
        self.assertEqual(reply.state, State.UP)

    def test_down_ignores_peer_up(self) -> None:
        # No transition is defined for Down when the peer says Up.
        sd = self.server_disc()

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=sd))
        self.assertEqual(reply.state, State.DOWN)

    def test_init_stays_init_when_peer_is_down(self) -> None:
        first = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(first.state, State.INIT)

        second = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(second.state, State.INIT)

    def test_init_to_up_when_peer_is_up(self) -> None:
        first = self.assertAnswered(self.packet(state=State.DOWN))

        reply = self.assertAnswered(self.packet(
            state=State.UP, your_disc=first.my_disc))
        self.assertEqual(reply.state, State.UP)

    def test_up_to_down_when_peer_is_down(self) -> None:
        up = self.bring_up()

        reply = self.assertAnswered(self.packet(
            state=State.DOWN, your_disc=up.my_disc))
        self.assertEqual(reply.state, State.DOWN)
        self.assertEqual(reply.diag, Diag.NEIGHBOR_DOWN,
                         "diagnostic is not 'Neighbor Signaled Session Down'")

    def test_up_to_down_when_peer_is_admin_down(self) -> None:
        up = self.bring_up()

        reply = self.assertAnswered(self.packet(
            state=State.ADMIN_DOWN, your_disc=up.my_disc))
        self.assertEqual(reply.state, State.DOWN)
        self.assertEqual(reply.diag, Diag.NEIGHBOR_DOWN)

    def test_init_to_down_when_peer_is_admin_down(self) -> None:
        init = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(init.state, State.INIT)

        reply = self.assertAnswered(self.packet(
            state=State.ADMIN_DOWN, your_disc=init.my_disc))
        self.assertEqual(reply.state, State.DOWN)
        self.assertEqual(reply.diag, Diag.NEIGHBOR_DOWN)

    def test_down_stays_down_when_peer_is_admin_down(self) -> None:
        reply = self.assertAnswered(self.packet(state=State.ADMIN_DOWN))
        self.assertEqual(reply.state, State.DOWN)
        self.assertEqual(reply.diag, Diag.NONE)

    def test_session_comes_up_again(self) -> None:
        # After a failure the same handshake brings the session back.
        up = self.bring_up()
        self.assertAnswered(self.packet(
            state=State.DOWN, your_disc=up.my_disc))

        again = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(again.state, State.INIT)

        reply = self.assertAnswered(self.packet(
            state=State.INIT, your_disc=again.my_disc))
        self.assertEqual(reply.state, State.UP)

    def test_no_final_without_poll(self) -> None:
        # Section 6.5: only a Poll is answered with a Final.
        self.send(self.packet(state=State.DOWN))

        reply = self.peer.receive(lambda p: p.final, 0.3)
        self.assertIsNone(reply)

    def test_final_answer_has_poll_clear(self) -> None:
        # Section 6.5: the answer to a Poll has Poll clear and Final set.
        reply = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertTrue(reply.final)
        self.assertFalse(reply.poll)

    def test_discarded_packet_does_not_change_state(self) -> None:
        # A packet which fails validation must not move the session.
        sd = self.server_disc()

        self.send(self.packet(state=State.INIT, your_disc=sd, version=2))
        self.send(self.packet(state=State.INIT, your_disc=sd,
                              detect_mult=0))

        reply = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertEqual(reply.state, State.INIT,
                         "session state is not the one from the Down packet")


if __name__ == "__main__":
    unittest.main()
