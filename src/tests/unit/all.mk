#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.unit

#
#  The files are put here in order.  Later tests need
#  functionality from earlier test.
#
FILES  := \
	data_types.txt \
	radius_rfc.txt \
	radius_errors.txt \
	radius_extended.txt \
	radius_lucent.txt \
	radius_wimax.txt \
	radius_tunnel.txt \
	radius_vendor.txt \
	radius_unit.txt \
	radius_struct.txt \
	eap_aka_encode.txt \
	eap_aka_decode.txt \
	eap_aka_error.txt \
	eap_sim_encode.txt \
	eap_sim_decode.txt \
	eap_sim_error.txt \
	dhcpv4.txt \
	dhcpv6_microsoft.txt \
	dhcpv6_rfc3315.txt \
	dhcpv6_rfc3319.txt \
	dhcpv6_rfc3646.txt \
	dhcpv6_rfc6355.txt \
	regex.txt \
	escape.txt \
	condition.txt \
	xlat.txt \
	ethernet.txt

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more

$(eval $(call TEST_BOOTSTRAP))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	${Q}echo UNIT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/test.unit; \
		exit 1; \
	fi
