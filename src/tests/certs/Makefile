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
	@$(MAKE) -C tmp
	@cp tmp/ca.* tmp/server.* tmp/client.* tmp/ocsp.* tmp/dh .
