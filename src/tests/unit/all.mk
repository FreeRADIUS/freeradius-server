#
#  Unit tests for individual pieces of functionality.
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES  := \
	rfc.txt \
	errors.txt \
	extended.txt \
	lucent.txt \
	wimax.txt \
	escape.txt \
	condition.txt \
	xlat.txt \
	vendor.txt \
	dhcp.txt \
	tlv.txt \
	tunnel.txt \
	dict.txt \
	regex.txt \
	ethernet.txt

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/unit
$(BUILD_DIR)/tests/unit:
	${Q}mkdir -p $@

.PHONY: $(BUILD_DIR)/share
$(BUILD_DIR)/share:
	${Q}mkdir -p $@

#
#  We need $INCLUDE in the output file, so we pass 2 parameters to 'echo'
#  No idea how portable that is...
#
$(BUILD_DIR)/share/dictionary: $(top_srcdir)/share/dictionary $(top_srcdir)/share/dictionary.dhcp $(top_srcdir)/src/tests/unit/dictionary.unit | $(BUILD_DIR)/share
	${Q}rm -f $@
	${Q}for x in $^; do \
		echo '$$INCLUDE ' "$$x" >> $@; \
	done

#
#  Files in the output dir depend on the unit tests
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% $(BUILD_DIR)/bin/unit_test_attribute $(TESTBINDIR)/unit_test_attribute $(BUILD_DIR)/share/dictionary | $(BUILD_DIR)/tests/unit
	${Q}echo UNIT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(BUILD_DIR)/share $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(BUILD_DIR)/share $<"; \
		exit 1; \
	fi
	${Q}touch $@

#
#  Get all of the unit test output files
#
TESTS.UNIT_FILES := $(addprefix $(BUILD_DIR)/tests/unit/,$(FILES))

$(TESTS.UNIT_FILES): $(TESTS.DICT_FILES)

#
#  Depend on the output files, and create the directory first.
#
tests.unit: $(TESTS.UNIT_FILES)
