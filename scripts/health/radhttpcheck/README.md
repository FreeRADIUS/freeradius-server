# radhttpcheck
## Introduction
No cloud providers currently support sending RADIUS packets from their cloud native load balancers.

In order to actively monitor FreeRADIUS (or other RADIUS servers) in these environments, we need to
provide a HTTP service which sends RADIUS packets on behalf of the load balancer

This script provides a HTTP <-> RADIUS gateway, sending pre-configured RADIUS packets to an ip/port
and translating the response (or lack of response) to a HTTP response code.

## How it works
The configuration file allows one or more healthchecks to be configured, these healthchecks, when accessed
with HTTP GET, send a RADIUS request to a given ip/port (usually localhost, port 1812/1813).

The underlying HTTP library forks a new thread for each access, and each thread opens a new UDP
socket to ensure there are never conflicting source port or IP allocations.

No caching is performed, and each HTTP GET results in a new RADIUS packet being sent.  One or more
retries can be configured, with an N second timeout.

The process is entirely synchronous, which, given the relatively low volume of requests, is fine,
but you should ensure the healthcheck server is NOT accessible from the wider internet.

## Configuration
By default this script loads its configuration from `radhttpcheck.yml`

### Example
```yaml
listen:
  # Address we bind to
  ipaddr: '*'
  # HTTP port to listen on
  port: 8080
# URLs the healthcheck script will respond on, and the various types of requests they create
healthchecks:
  '/acct':
    port: 1813
    secret: testing123
    type: Accounting-Request
    retries: 3
    timeout: 1
    attributes:
      Acct-Session-Id: '0123456789'
      Acct-Status-Type: 'Start'
  '/auth':
    port: 1812
    secret: testing123
    type: Access-Request
  '/customEndpoint':
    port: 101812
    secret: foo
    type: 29
dictionary: /usr/local/radhttpcheck/dictionary
```

### `listen`
| attr          | default          | comment                                                  |
|---------------|------------------|----------------------------------------------------------|
| `ipaddr`      | `*`              | IP address listen for HTTP requests on. `*` is any.      |
| `port`        | `8080`           | Port we listen for HTTP requests on.                     |

### `healthchecks`

healthchecks is a dictionary with keys representing the URL that will trigger the healthcheck
and a dict containing the healthcheck configuration.

| attr          | default          | comment                                                  |
|---------------|------------------|----------------------------------------------------------|
| `server`      | `127.0.0.1`      | Where we send RADIUS requests to.                        |
| `port`        | set by type      | UDP port we send RADIUS requests to.                     |
| `secret`      | `testing123`     | RADIUS shared secret.                                    |
| `type`        | set by port      | Request packet type, `Access-Request`, `Accounting-Request`, `CoA-Request`, `Disconnect-Request`, `Status-Server`, or the packet code as an integer value. |
| `retries`     | `1`              | How many times we resend the request on timeout.         |
| `timeout`     | `1`              | How long we wait for a response.                         |
| `attributes`  | `{}`             | A dictionary of RADIUS attributes to send in the request, each attribute can be sent once. |
| `require_ack` | False            | Whether we require a positive acknowledgement i.e. `Access-Accept` for `Access-Request`, `CoA-ACK` for `CoA-Request` to count the healthcheck as successful.  When `False`, any response is OK. |

### `dictionary`

The path to the RADIUS attribute dictionary file, defaults to `dictionary`.

## Dictionary format and contents

A pyrad compatible dictionary file 'dictionary' is available in this directory.  This is the aggregate
of RFC 2865, 2866, and 2869 with any FreeRADIUS v4 syntax that PyRad didn't like removed.

You may customise it to add additional vendor attributes, but be aware PyRad uses the old style v3
dictionary format.

## HTTP response codes

As this script mostly acts as a gateway between the HTTP client, and RADIUS server, HTTP gateway response
codes are used to indicate errors.

| code          | meaning           | comment                                                  |
|---------------|-------------------|----------------------------------------------------------|
| `200`         | Success           | We received a valid response from the RADIUS server.     |
| `500`         | Script failure    | An internal error occurred in the healthcheck script.     |
| `502`         | Invalid response  | Either the response packet was malformed or failed validation (bad shared secret), or `require_ack` was enabled, and the response contained a NAK response like `Access-Reject`. |
| `504`         | Timeout           | No response received from the RADIUS server.             |

In all cases a JSON blob will be received in the format `{ 'msg": "<extended response message>" }`

## Built-in HTTP endpoints

| endpoint      | usage             | comment                                                  |
|---------------|-------------------|----------------------------------------------------------|
| `/alwaysOk`   | CoA/DM src ports  | Sometimes CoA/DM src ports need to be routed via a loadbalancer, this endpoint ensures the healthchecks never fail so long as the CoA/DM server is reachable. |
| `/list`       | Show healthchecks | List all the available healthchecks.                     |
