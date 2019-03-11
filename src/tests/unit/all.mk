#
#  Unit tests for individual pieces of functionality.
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES  := \
	radius_rfc.txt \
	radius_errors.txt \
	radius_extended.txt \
	radius_lucent.txt \
	radius_wimax.txt \
	radius_tunnel.txt \
	radius_vendor.txt \
	radius_tlv.txt \
	radius_unit.txt \
	radius_struct.txt \
	eap_aka_encode.txt \
	eap_aka_decode.txt \
	eap_aka_error.txt \
	eap_sim_encode.txt \
	eap_sim_decode.txt \
	eap_sim_error.txt \
	dhcpv4.txt \
	dhcpv6.txt \
	regex.txt \
	escape.txt \
	condition.txt \
	xlat.txt \
	ethernet.txt

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more


#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/unit
$(BUILD_DIR)/tests/unit:
	${Q}mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% $(BUILD_DIR)/bin/unit_test_attribute $(TESTBINDIR)/unit_test_attribute | $(BUILD_DIR)/tests/unit
	${Q}echo UNIT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r \"$@\" $<"; \
		exit 1; \
	fi

#
#  Get all of the unit test output files
#
TESTS.UNIT_FILES := $(addprefix $(BUILD_DIR)/tests/unit/,$(FILES))

$(TESTS.UNIT_FILES): $(TESTS.DICT_FILES)

#
#  Depend on the output files, and create the directory first.
#
tests.unit: $(TESTS.UNIT_FILES)
