#
#  See README.md
#
.PHONY: all
all:
	@rm -rf tmp
	@mkdir -p tmp
	@cp -a ../../../raddb/certs/ tmp/
	@$(MAKE) -C tmp distclean
	@sed 's/^default_days.*= 60/default_days = 365/' < tmp/ca.cnf > tmp/foo
	@mv tmp/foo tmp/ca.cnf
	@sed 's/^default_days.*= 60/default_days = 365/' < tmp/server.cnf > tmp/foo
	@mv tmp/foo tmp/server.cnf
	@sed 's/^default_days.*= 60/default_days = 365/' < tmp/client.cnf > tmp/foo
	@mv tmp/foo tmp/client.cnf
	@sed 's/^default_days.*= 60/default_days = 365/' < tmp/ocsp.cnf > tmp/foo
	@mv tmp/foo tmp/ocsp.cnf
	@$(MAKE) -C tmp
	@cp tmp/ca.* tmp/server.* tmp/client.* tmp/ocsp.* tmp/dh .

.PHONY: print
print:
	@openssl x509 -text -in ca.pem
	@openssl x509 -text -in server.pem
	@openssl x509 -text -in client.pem

.PHONY: verify
verify:
	@openssl verify -CAfile ca.pem server.pem
	@openssl verify -CAfile ca.pem ocsp.pem
	@c_rehash .
	@openssl verify -CApath . client.pem
