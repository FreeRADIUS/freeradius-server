#!/usr/bin/env python3
"""
The Bidirectional Forwarding Detection (BFD) process module and its sections.

BFD names its sections after the session states.  Each section name is `recv`
or `send` followed by `Admin-Down`, `Down`, `Init`, or `Up`, for example
`recv Down` and `send Up`.  A `recv` section runs for a packet that the server
receives from the peer.  A `send` section runs for a packet that the server
sends to the peer.

The `only_state_changes` setting decides whether the sections run for every
packet or only for packets that change the state of the session.
"""

import unittest

from bfdlib import AbstractBfdTest, ServerConfig, State

STATES = ("Admin-Down", "Down", "Init", "Up")


def ran(text: str) -> str:
    """
    Return a pattern for the line that a section logs.  Each run also logs a
    trace of the expansion.  The trace has a '|' before the text, and the
    pattern does not match the trace.
    """
    return rf"^\(\d+\)\s+TEST {text}"


def logging_sections() -> str:
    """
    Return text that defines a section for each state and direction.  Each
    section logs the name of the section.
    """
    sections = ""

    for state in STATES:
        for direction in ("recv", "send"):
            sections += (f"\t{direction} {state} {{\n"
                         f"\t\t%log.info(\"TEST {direction} {state}\")\n"
                         "\t}\n\n")

    return sections


class EverySectionTest(AbstractBfdTest):
    """With `only_state_changes = no`, every packet runs a section."""
    CONFIG = ServerConfig(only_state_changes=False,
                          sections=logging_sections())

    def test_recv_section_matches_state_of_packet(self) -> None:
        down = self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0))

        self.assertAnswered(self.packet(
            state=State.INIT, your_disc=down.my_disc))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Init"), 2.0))

        self.assertAnswered(self.packet(
            state=State.UP, your_disc=down.my_disc))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Up"), 2.0))

        self.assertAnswered(self.packet(
            state=State.ADMIN_DOWN, your_disc=down.my_disc))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Admin-Down"), 2.0))

    def test_recv_section_runs_when_state_does_not_change(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0))

        mark = self.server.log_mark()
        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0, mark),
            "no section ran for the second packet")

    def test_discarded_packet_runs_no_section(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0))

        mark = self.server.log_mark()
        self.send(self.packet(state=State.DOWN, version=2))
        self.assertIsNone(
            self.server.wait_for_log(ran("recv"), 0.5, mark),
            "a section ran for a packet which fails validation")

    def test_send_section_runs_for_periodic_packet(self) -> None:
        pkt = self.peer.receive(lambda p: not p.final, 3.0)
        self.assertIsNotNone(pkt, "server sent no periodic packet")

        self.assertIsNotNone(
            self.server.wait_for_log(ran("send Down"), 2.0),
            "the packet was sent without running its 'send' section")
        self.assertEqual(pkt.state, State.DOWN)

    def test_send_section_follows_state_of_session(self) -> None:
        down = self.assertAnswered(self.packet(state=State.DOWN))

        # The session is Init, so the next periodic packet is an Init.
        mark = self.server.log_mark()
        pkt = self.peer.receive(lambda p: not p.final, 3.0)
        self.assertIsNotNone(pkt, "server sent no periodic packet")
        self.assertEqual(pkt.state, State.INIT)
        self.assertEqual(pkt.your_disc, self.disc)
        self.assertEqual(pkt.my_disc, down.my_disc)

        self.assertIsNotNone(
            self.server.wait_for_log(ran("send Init"), 2.0, mark))


class StateChangeSectionTest(AbstractBfdTest):
    """
    With `only_state_changes = yes`, the default, a section runs only when the
    state of the session changes.
    """
    CONFIG = ServerConfig(only_state_changes=True,
                          sections=logging_sections())

    def test_recv_section_runs_when_state_changes(self) -> None:
        mark = self.server.log_mark()

        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0, mark))

    def test_recv_section_does_not_run_without_a_change(self) -> None:
        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNotNone(
            self.server.wait_for_log(ran("recv Down"), 2.0))

        # Init + Down is no change.
        mark = self.server.log_mark()
        self.assertAnswered(self.packet(state=State.DOWN))
        self.assertIsNone(
            self.server.wait_for_log(ran("recv"), 0.5, mark),
            "a section ran for a packet which did not change the state")

    def test_send_section_does_not_run(self) -> None:
        # Periodic packets go out without being shown to the server policy.
        pkt = self.peer.receive(lambda p: not p.final, 3.0)
        self.assertIsNotNone(pkt, "server sent no periodic packet")

        self.assertIsNone(
            self.server.wait_for_log(ran("send"), 0.3),
            "a 'send' section ran")


if __name__ == "__main__":
    unittest.main()
