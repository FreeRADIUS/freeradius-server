#
#  See README.md
#

#
#	Just to mute the WARNING messages complaining about the missing openssl.cnf
#
OPENSSL_CONF := /dev/null
export OPENSSL_CONF

.PHONY: all
all:
	@rm -rf tmp rsa ecc
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
	@mv tmp/rsa tmp/ecc .

.PHONY: print
print:
	@openssl x509 -text -in rsa/ca.pem
	@openssl x509 -text -in rsa/server.pem
	@openssl x509 -text -in rsa/client.pem
	@openssl x509 -text -in ecc/ca.pem
	@openssl x509 -text -in ecc/server.pem
	@openssl x509 -text -in ecc/client.pem

.PHONY: verify
verify:
	@openssl verify -CAfile rsa/ca.pem rsa/server.pem
	@openssl verify -CAfile rsa/ca.pem rsa/ocsp.pem
	@c_rehash rsa/
	@openssl verify -CApath rsa rsa/client.pem
	@openssl verify -CAfile ecc/ca.pem ecc/server.pem
	@openssl verify -CAfile ecc/ca.pem ecc/ocsp.pem
	@c_rehash ecc/
	@openssl verify -CApath ecc ecc/client.pem
