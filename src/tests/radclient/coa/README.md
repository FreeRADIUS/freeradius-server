#  Running Receive CoA with radclient

It's a bit messed up.

Edit `sites-enabled/default`, and change the `recv Access-Request` section:

```
recv Access-Request {
    if (User-Name == "coa") {
        Reply-Message := %exec('./build/make/jlibtool', '--mode=execute', './build/bin/local/radclient', '-d', 'raddb/', '-D', 'share/dictionary/', '-xx', '-t', '2', '-F', '-f', 'src/tests/radclient/coa/server_coa.txt,src/tests/radclient/exec/server_coa_reply.txt', 'localhost:37990', 'coa', 'testing123')
        accept
    }
    ...
```

Then in one terminal window, run the server from the top source directory:

```
./scripts/bin/radiusd -sf -xx -l stdout
```


Then in another terminal window, run radclient from the top source directory:

```
COA=src/tests/radclient/coa ./scripts/bin/radclient -xx -c 1 -F -o 37990 -A User-Name -f ${COA}/packet.txt,${COA}/reply.txt,${COA}/coa_reply.txt,${COA}/coa.txt localhost auth testing123
```