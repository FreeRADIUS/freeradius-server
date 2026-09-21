#!/bin/sh
exec openssl s_client -connect 127.0.0.1:2083 \
 -cert raddb/certs/rsa/client.pem \
 -key raddb/certs/rsa/client.key -pass pass:whatever \
 -CAfile raddb/certs/rsa/ca.pem
