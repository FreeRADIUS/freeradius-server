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
#  Files in the output dir depend on the bin tests, and on the binary
#  that we're running
#
$(BUILD_DIR)/tests/bin/%: $(DIR)/% $(TESTBINDIR)/% | $(BUILD_DIR)/tests/bin
	${Q}echo BIN-TEST $(notdir $@)
	${Q}TESTBIN="$(TESTBIN)" TESTBINDIR="$(TESTBINDIR)" DICT_DIR="$(DICT_DIR)" $<
	${Q}touch $@

#
#  Get all of the bin test output files
#
TEST.BIN_FILES := $(addprefix $(BUILD_DIR)/tests/bin/,$(FILES))

$(TEST.BIN_FILES): $(TEST.DICT_FILES)

#
#  Depend on the output files, and create the directory first.
#
test.bin: $(TEST.BIN_FILES)

.PHONY: clean.test.bin
clean.test.bin:
	${Q}rm -rf $(BUILD_DIR)/tests/bin/

clean.test: clean.test.bin
