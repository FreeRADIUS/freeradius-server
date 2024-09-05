our_path:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

all: ${our_path}/freeradius.pp.bz2

%.mod: %.te
	@checkmodule -M -m -o $@ $<

%.pp: %.mod
	@semodule_package -o $@ -m $<

%.pp.bz2: %.pp
	@bzip2 -9 $<

.PHONY: clean
clean:
	@cd "${our_path}"; \
