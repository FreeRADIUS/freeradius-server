FILES  := \
	atomic_queue_test 	\
	control_test 		\
	dhcpclient		\
	message_set_test	\
	radclient		\
	radict 			\
	radmin			\
	radsniff 		\
	radsnmp 		\
	radwho 			\
	rbmonkey 		\
	ring_buffer_test 	\
	rlm_redis_ippool_tool 	\
	smbencrypt 		\
	unit_test_attribute 	\
	unit_test_map 		\
	unit_test_module


DICT_DIR := $(top_srcdir)/share/dictionary

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/bin
$(BUILD_DIR)/tests/bin:
	${Q}mkdir -p $@

#
#  Files in the output dir depend on the bin tests
#
$(BUILD_DIR)/tests/bin/%: $(DIR)/% | $(BUILD_DIR)/tests/bin
	${Q}echo BIN-TEST $(notdir $@)
	${Q}TESTBIN="$(TESTBIN)" TESTBINDIR="$(TESTBINDIR)" DICT_DIR="$(DICT_DIR)" $<
	${Q}touch $@

#
#  Get all of the bin test output files
#
TESTS.BIN_FILES := $(addprefix $(BUILD_DIR)/tests/bin/,$(FILES))

$(TESTS.BIN_FILES): $(TESTS.DICT_FILES)

#
#  Depend on the output files, and create the directory first.
#
tests.bin: $(TESTS.BIN_FILES)

.PHONY: clean.tests.bin
clean.tests.bin:
	${Q}rm -rf $(BUILD_DIR)/tests/bin/

