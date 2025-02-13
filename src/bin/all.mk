SUBMAKEFILES := \
    radclient.mk \
    radclient-ng.mk \
    radict.mk \
    radiusd.mk \
    radlock.mk \
    radsniff.mk \
    radsnmp.mk \
    radsizes.mk \
    radtest.mk \
    dhcpclient.mk \
    unit_test_attribute.mk \
    unit_test_map.mk \
    unit_test_module.mk \
    checkrad.mk

#
#  Add the list of protocols to be fuzzed here Each protocol needs to
#  have a test point for packet decoding.  See
#  src/protocols/radius/decode.c for an example.
#
#  The fuzzer binary needs special magic to run, as it doesn't parse
#  command-line options.  See fuzzer.mk for details.
#
FUZZER_PROTOCOLS = radius dhcpv4 dhcpv6 dns tacacs vmps tftp util bfd cbor der

#
#  Add the fuzzer only if everything was built with the fuzzing flags.
#
ifneq "$(findstring fuzzer,${CFLAGS})" ""

#
#  Put the output artifacts into the build directory, but only if the
#  variable is not already set by the environment or make files.
#
FUZZER_ARTIFACTS ?= ${BUILD_DIR}/fuzzer

#
#  Time out "test.fuzzer.foo" after this number of seconds
#
FUZZER_TIMEOUT   ?= 10

#
#  Define a function to do all of the same thing.
#
define FUZZ_PROTOCOL
src/bin/fuzzer_${1}.c: src/bin/fuzzer.c
	$${Q}sed 's/XX_PROTOCOL_XX/${1}/g' < $$^ > $$@


src/bin/fuzzer_${1}.mk: src/bin/fuzzer.mk
	$${Q}sed 's/$$$$(PROTOCOL)/${1}/g' < $$^ > $$@

SUBMAKEFILES += fuzzer_${1}.mk
endef

$(foreach X,${FUZZER_PROTOCOLS},$(eval $(call FUZZ_PROTOCOL,${X})))

.PHONY: fuzzer.help
fuzzer.help:
	@git-lfs env > /dev/null 2>&1 || echo "Please install 'git-lfs' in order to use the fuzzer corpus files."
	@echo To run the fuzzer, please use one of:
	@echo
	@for _p in $(PROTOCOLS); do echo "    make fuzzer.$$_p"; done
	@echo

test.fuzzer: $(addprefix test.fuzzer.,$(FUZZER_PROTOCOLS))

test.fuzzer.crash: $(addsuffix .crash,$(addprefix test.fuzzer.,$(FUZZER_PROTOCOLS)))

test.fuzzer.merge: $(addsuffix .merge,$(addprefix test.fuzzer.,$(FUZZER_PROTOCOLS)))

else
.PHONY: fuzzer.help $(foreach X,${FUZZER_PROTOCOLS},fuzzer.${X})
fuzzer.help $(foreach X,${FUZZER_PROTOCOLS},fuzzer.${X}) test.fuzzer:
	@echo "The server MUST be built with '--enable-fuzzer'"
endif
