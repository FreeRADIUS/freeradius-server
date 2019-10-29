SUBMAKEFILES := \
    radclient.mk \
    radict.mk \
    radiusd.mk \
    radsniff.mk \
    radwho.mk \
    radsnmp.mk \
    radlast.mk \
    radtest.mk \
    radzap.mk \
    unit_test_attribute.mk \
    unit_test_map.mk \
    unit_test_module.mk \
    checkrad.mk

#
#  Add the fuzzer only if everything was built with the fuzzing flags.
#
ifneq "$(findstring -fsanitize=fuzzer,${CFLAGS})" ""

#
#  Define a function to do all of the same thing.
#
define FUZZ_PROTOCOL
src/bin/fuzzer_${1}.mk: src/bin/fuzzer.mk
	$${Q}echo "PROTOCOL=${1}" > $$@
	$${Q}cat $$^ >> $$@

SUBMAKEFILES += fuzzer_${1}.mk
endef

#
#  Add the list of protocols to be fuzzed here Each protocol needs to
#  have a test point for packet decoding.  See
#  src/protocols/radius/decode.c for an example.
#
PROTOCOLS = radius dhcpv6

$(foreach X,${PROTOCOLS},$(eval $(call FUZZ_PROTOCOL,${X})))
endif
