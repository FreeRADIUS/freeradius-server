#
#	Test name
#
TEST  := test.vmps
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
VMPS_BUILD_DIR  := $(BUILD_DIR)/tests/vmps
VMPS_RADIUS_LOG := $(VMPS_BUILD_DIR)/radiusd.log
VMPS_GDB_LOG    := $(VMPS_BUILD_DIR)/gdb.log

#
#	Local VQCLI client
#
VQCLI := src/protocols/vmps/vqpcli.pl

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

#
#	Run the VMPS commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(Q)echo "VMPS-TEST INPUT=$(TARGET) VMPS_ARGV=\"$(ARGV)\""
	$(Q)[ -f $(dir $@)/radiusd.pid ] || exit 1
	$(Q)if ! $(VQCLI) -s 127.0.0.1 -p $(PORT) $(ARGV) 1> $(FOUND) 2>&1; then \
		echo "FAILED";                                            \
		cat $(FOUND);                                             \
		rm -f $(BUILD_DIR)/tests/test.vmps;                       \
		$(MAKE) --no-print-directory test.vmps.radiusd_kill;      \
		echo "RADIUSD: $(RADIUSD_RUN)";                           \
		echo "VQCLI:   $(VQCLI) -s 127.0.0.1 -p $(PORT) $(ARGV)"; \
		exit 1;                                                   \
	fi
#
#	Checking.
#
#	1. diff between src/test/vmps/$test.out & build/test/vmps/$test.out
#
	$(Q)if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then   \
		echo "VMPS FAILED $@";                                       \
		echo "RADIUSD:    $(RADIUSD_RUN)";                           \
		echo "VQCLI:      $(VQCLI) -s 127.0.0.1 -p $(PORT) $(ARGV)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)";  \
		echo "If you did some update on the VMPS code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                     \
		diff $(EXPECTED) $(FOUND);                                   \
		rm -f $(BUILD_DIR)/tests/test.vmps;                          \
		$(MAKE) --no-print-directory test.vmps.radiusd_kill;         \
		exit 1;                                                      \
	fi
	$(Q)touch $@

$(TEST):
	$(Q)$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
