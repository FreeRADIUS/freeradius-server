#
#  Unit tests for radius_pairmove(), using acutest.
#
SUBMAKEFILES := pairmove_tests.mk

PAIRMOVE_TESTS := pairmove_tests

.PHONY: tests.pairmove
tests.pairmove: $(addprefix $(BUILD_DIR)/tests/pairmove/,$(PAIRMOVE_TESTS))

$(BUILD_DIR)/tests/pairmove:
	${Q}mkdir -p $@

#
#  Run each test binary.  A test which passes touches its stamp file, so
#  re-running "make tests.pairmove" only re-runs what changed.
#
#  DICT_DIR tells the binary where to find the dictionaries, since they are
#  not installed yet.
#
$(BUILD_DIR)/tests/pairmove/%: $(TESTBINDIR)/% | $(BUILD_DIR)/tests/pairmove
	${Q}echo "PAIRMOVE-TEST $(notdir $@)"
	${Q}DICT_DIR=$(top_srcdir)/share $(TESTBIN)/$(notdir $@)
	${Q}touch $@

.PHONY: clean.tests.pairmove
clean.tests.pairmove:
	${Q}rm -rf $(BUILD_DIR)/tests/pairmove

clean.test: clean.tests.pairmove
