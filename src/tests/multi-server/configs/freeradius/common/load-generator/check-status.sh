#!/bin/bash
#
#  Check Status-Server on port 1820.  The server's
#  recv Status-Server section reports a PASS or FAIL to the test framework
#  based on number of responses received.
#
printf 'User-Name := "testuser"\nUser-Password := "testpass"\n' | /usr/bin/radclient -x -t 2 -r 1 localhost:1820 status testing123
