# BFD tests

These tests check the Bidirectional Forwarding Detection (BFD) code in
`src/listen/bfd`, `src/protocols/bfd`, and `src/process/bfd` against RFC 5880.

Each test starts a radiusd with a BFD listener and one peer. The test then
acts as that peer from a UDP socket. The test sends hand-built BFD packets to
the server and checks the packets that come back.

## Running the tests

    make test.bfd

To run one file without make, from the top of the source tree:

    python3 src/tests/bfd/session_states.py

The tests run `scripts/bin/radiusd`. Set `BFD_RADIUSD` to run a different
server. Set `OUTPUT` to choose the directory where the tests write the
configuration and server log. Without `OUTPUT`, the tests write to a temporary
directory. Each test has its own directory, named after the test.

Every test starts its own server. The server keeps one session for each peer
address, and a session carries its state from one packet to the next. A shared
server would make each test depend on the tests that ran before it.

## The files

| File | What it checks |
| --- | --- |
| `packet_validation.py` | The checks of RFC 5880 Section 6.8.6 that discard bad packets. |
| `session_states.py` | The state changes of RFC 5880 Section 6.8.6, from 'Down' through 'Init' to 'Up' and back. |
| `authentication.py` | The five authentication types of RFC 5880 Section 6.7, in both directions. |
| `timing.py` | Transmit intervals, jitter (random variation of the transmit interval), detection time, and Demand mode (RFC 5880 Section 6.6). |
| `process_sections.py` | The `recv` and `send` sections that run for each state. |
| `bfdlib.py` | The packet encoder and decoder, the code that starts the server, and the test base class. |

## How a test reads the state of the server

A packet with the Poll bit set makes the server answer at once. The answer is a
packet with the Final bit set that carries the current state of the server
session (RFC 5880 Section 6.5). The tests use this exchange to read the state
without waiting for a timer. A negative test sends a bad packet with the Poll
bit set and checks that the server does not answer. No answer means that the
server discarded the packet. Before sending the bad packet, each negative test
checks that the server does answer a good packet.

## Known failures

Some tests are marked `expectedFailure`. Each mark records a difference between
the code and RFC 5880. While the difference exists, the test reports an
expected failure. After the code is fixed, the test reports an unexpected
success. When that happens, remove the `expectedFailure` mark from the test.

The RFC text was not available when these tests were written. Where this list
quotes RFC 5880, the quote comes from a comment in `src/listen/bfd/session.c`.
Check each item against the RFC before acting on it.

1. **The server does not compare the configured authentication type with the
   type in the packet.**
   The server picks the check from the type in the packet, not from the type of
   the session (see `bfd_authenticate()`). A session set to `keyed-sha1`
   accepts a `simple` password packet that carries the same secret. A comment
   in `bfd_session_process()` quotes RFC 5880 Section 6.8.6: the packet is
   authenticated "based on the authentication type in use".

2. **A session that is not 'Up' sends faster than once a second.**
   A comment in `bfd_session_process()` quotes RFC 5880 Section 6.8.3: when
   the session is not 'Up', the transmit interval must be at least one second.
   The server applies the limit only when the state changes. Because of that, a
   new session sends at the configured interval until the session receives a
   packet from its peer. A test measured a gap of 95 milliseconds with a
   configured interval of 100 milliseconds.

3. **The configured transmit interval is not used once the session is 'Up'.**
   On a state change to any state other than 'Up', the server sets the
   transmit interval to one second. After the session becomes 'Up', nothing
   restores the configured value.

4. **The server uses its own Detect Mult to calculate the detection time.**
   `bfd_set_timeout()` multiplies the detection time by the Detect Mult of the
   session configuration (`max_timeouts`). A comment in `bfd_session_process()`
   refers to RFC 5880 Section 6.8.4 for the detection time, and the author of
   these tests recalls that the RFC uses the Detect Mult of the peer. Check
   that against the RFC. A test with a server value of 2 and a peer value of 5
   showed the session dropping after 350 milliseconds. The same test with a
   server value of 5 kept the session up.

## Not covered

- Echo mode. The server does not support echo mode, and always sends zero for
  the Required Min Echo RX Interval.
- Poll Sequences that the server starts when its own intervals change.
- Peers at more than one address. The tests use only `127.0.0.1`.
- The rules of RFC 5881 for BFD over IP. These rules cover the UDP port numbers
  and a Time To Live (TTL) of 255.
