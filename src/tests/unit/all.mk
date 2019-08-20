#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := tests.unit

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
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
	dhcpv6.txt \
	regex.txt \
	escape.txt \
	condition.txt \
	xlat.txt \
	ethernet.txt

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more


OUTPUT := $(subst $(top_srcdir)/src,$(BUILD_DIR),$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

#
#  Create the output directory
#
.PHONY: $(OUTPUT)
$(OUTPUT):
	${Q}mkdir -p $@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $(OUTPUT),$(notdir $(FILES)))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#
#  The output files also depend on the directory
#  and on the previous test.
#
$(FILES.$(TEST)): | $(OUTPUT)

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $(FILES.$(TEST))
	${Q}touch $@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the ouput directory and files.
#
#  Note that we have to specify the actual filenames here, because
#  of stupidities with GNU Make.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	${Q}rm -rf $(BUILD_DIR)/tests/unit $(BUILD_DIR)/tests/tests.unit

clean.test: clean.$(TEST)

#
#  And the actual script to run each test.
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	${Q}echo UNIT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/tests.unit; \
		exit 1; \
	fi
