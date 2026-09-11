#
#  Unit tests for the library APIs, using acutest.
#
SUBMAKEFILES := value_tests.mk pair_tests.mk conffile_tests.mk

API_TESTS := value_tests pair_tests conffile_tests

.PHONY: tests.api
tests.api: $(addprefix $(BUILD_DIR)/tests/api/,$(API_TESTS))

$(BUILD_DIR)/tests/api:
	${Q}mkdir -p $@

#
#  Run each test binary.  A test which passes touches its stamp file, so
#  re-running "make tests.api" only re-runs what changed.
#
#  TESTBIN handles both the shared and the static library cases, and sets
#  FR_LIBRARY_PATH where that is needed.  DICT_DIR tells the binaries where
#  to find the dictionaries, since they are not installed yet.
#
$(BUILD_DIR)/tests/api/%: $(TESTBINDIR)/% | $(BUILD_DIR)/tests/api
	${Q}echo "API-TEST $(notdir $@)"
	${Q}DICT_DIR=$(top_srcdir)/share $(TESTBIN)/$(notdir $@)
	${Q}touch $@

.PHONY: clean.tests.api
clean.tests.api:
	${Q}rm -rf $(BUILD_DIR)/tests/api

clean.test: clean.tests.api
