# Performance test framework

These tests should be run manually for now.

In one terminal window, start up the `ack` virtual server.  This
server just "acks" every request it gets.

```bash
./run -n ack
```

In one terminal window, start up the `proxy` virtual server.  This
server just proxies every request it gets, to the `ack` server.

```bash
./run -n proxy
```

And then send the `proxy` server packets.

## Less Debug Output

For less debug output, use the `quiet` script.  This will run the
server in the foreground, and log to `stdout`:

```bash
./quiet -n ack
```

and

```bash
./quiet -n proxy
```

## Stress Testing

Run the stress tests:

```bash
./stress
```

You will need `radperf` in your `$PATH`.
