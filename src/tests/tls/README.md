# Tests for TLS

You will need at least 3 terminal windows:

1. Home Server

```
./radiusd-home.sh
```

This server receives Access-Request packets over TLS, and sends Access-Accept.

2. Proxy server

```
./radiusd-proxy.sh
```

This server receives Access-Request packets over UDP, and proxies them to the home server.

3. Client(s)

Send one packet:

```
./radclient.sh
```

Send 500,000 packets:

```
./radclient.sh -c 500000
```

You can also send accounting packets:

```
./radacct.sh
```

