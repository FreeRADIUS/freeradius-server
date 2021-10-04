=======================
Tests for radsec flows.
=======================

                                 RADIUS CoA
       ┌─────────────────────────────────────────────────────────────┐
       │                                                             │
┌──────▼───────┐             ┌────────────────┐              ┌───────┴────────┐
│              │             │                │  RADSEC CoA  │                │
│   radiusd    │  RADIUS CoA │    radiusd     ◄──────────────┤    radiusd     │
│              ◄─────────────┤                │  RADSEC Auth │                │
│  CoA Server  │             │  Proxy Server  ├──────────────►  Home Server   │
│              │             │                │              │                │
└──────────────┘             └───────▲────────┘              └───────▲────────┘
                                     │                               │
                                     │ RADIUS                        │ RADIUS
                                     │ Auth                          │ CoA
                             ┌───────┴────────┐              ┌───────┴────────┐
                             │   radclient    │              │   radclient    │
                             └────────────────┘              └────────────────┘


FreeRADIUS common configuration is located (obviously) in
src/tests/radsec/radddb directory. Specific configurations for separate radiusd
instances are located under their respective directories: config-coa,
config-proxy, config-home.

Each test is a pair of two files ending with \*.request and \*.reply.

To run these tests separately, make sure you run 'make test' from the root
directory beforehand.

Request files.
==============

\*.request file specifies attributes to be sent.

The name of the file (the part after the dash) specifies the type of the request
to be sent.

For example 1.basic-auth.request sends an auth request and 2.basic-coa.request
sends coa.

* Authentication requests.
--------------------------
Radclient sends plain RADIUS Access-Request to Proxy Server. Proxy Server then
proxies this authentication request with RADSEC to Home Server. An opened TLS
tunnel is used later to accept CoA requests from Home Server.

* CoA requests.
---------------
Radclient sends plain RADIUS CoA request to Home Server. Depending on the
attributes Home Server does one of the following:

- Originates CoA request to Proxy Server with RADSEC - original flow. This is
the regular flow where Proxy Server acts as a TCP server and Home Server (as
a TCP client) first needs to establish a connection to it.

- Originates CoA request to Proxy Server with RADSEC - 'single tunnel flow'.
This is the new flow where Proxy Server can accept CoA requests from Home Server
within the same tunnel that it has opened for Access-Request. In this case, the
Proxy Server is still a TCP client yet in terms of RADIUS protocol it acts as
a CoA Server.

In both of these two cases, the Proxy Server forwards a CoA request to CoA
Server to complete the flow. As an example CoA Server responds with CoA-ACK,
then in turn Proxy Server responds with CoA-ACK to Home Server and the flow
completes.

- Originates CoA request directly to CoA Server. Although this is not a RADSEC
flow, that is also good to check.


Reply files.
============

\*.reply file specify a result to be expected for the corresponding \*.request
file.


For each such pair of \*.request \*.reply files runtest.sh is run.

This shell script sends a request with radclient.

Several freeRADIUS instances process requests and add attributes to be checked.
In the end of the flow all cumulative attributes are written to the detail_test
file for later checking.

The runtest.sh checks the result following a \*.reply file.

After test is performed a new directory is created with name "$TEST_NAME.result"
where all intermediate files realted to the test are located, an example of the
directory structure is like follows:

ok                           - status file: either ok or fail
detail_test                  - helper file to save attributes by freeRADIUS
2.ipaddrtls-coa.reply.tmp    - reply file w/o internal commands (e.g delay)
fr-home-2.ipaddrtls-coa.log  - a part of freeRADIUS logs related to the test
fr-coa-2.ipaddrtls-coa.log   - the same just for radiusd CoA Server
fr-proxy-2.ipaddrtls-coa.log - the same just for radiusd Proxy Server
radclient.log                - logs for radclient
result-2.ipaddrtls-coa.log   - combined and aggregated radclient.log and
                             - detail_test to be checked against \*.reply file
