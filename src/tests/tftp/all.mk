TFTP_BUILD_DIR  := $(BUILD_DIR)/tests/tftp

#
#	We need the 'tftpy' Python3 module to excute TFTP tests
#	Needed by scripts/tftp/tftpy_client
#
$(TFTP_BUILD_DIR)/depends.mk:
	@mkdir -p $(dir $@)
	@(which tftpy_client.py 1> /dev/null 2>&1 && echo WITH_TFTP=yes || echo WITH_TFTP=no) > $@

-include $(TFTP_BUILD_DIR)/depends.mk

#
#	Unit tests for scripts/TFTP/TFTP_client against the radiusd/proto_TFTP.
#
ifeq "$(WITH_TFTP)" "yes"
#
#	Test name
#
TEST  := test.tftp
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
TFTP_BUILD_DIR  := $(BUILD_DIR)/tests/tftp
TFTP_RADIUS_LOG := $(TFTP_BUILD_DIR)/radiusd.log
TFTP_GDB_LOG    := $(TFTP_BUILD_DIR)/gdb.log

#
#	Local TFTP client
#
TFTPLIENT := scripts/tftp/tftpy_client

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

#
#	Run the TFTP_client commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(eval FILE     := $(shell grep "#.*FILE:" $< | cut -f2 -d ':'))
	$(eval EXPECTED := $(top_srcdir)/raddb/mods-config/tftp/$(FILE))
	$(eval FOUND    := $(TFTP_BUILD_DIR)/$(FILE))

	$(Q)echo "TFTP-TEST INPUT=$(TARGET) FILE=\"$(FILE)\" TFTP_ARGV=\"$(ARGV)\""
	$(Q)[ -f $(dir $@)/radiusd.pid ] || exit 1
	$(Q)if ! $(TFTPLIENT) -H localhost -p $(PORT) -q -D $(FILE) -o $(FOUND) $(ARGV) 2>&1; then \
		echo "FAILED";                                              \
		cat $(FOUND);                                               \
		rm -f $(BUILD_DIR)/tests/test.tftp;                       \
		$(MAKE) --no-print-directory test.tftp.radiusd_kill;      \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "TFTPLIENT: $(TFTPLIENT) -H localhost -p $(PORT) -q -D $(FILE) -o $(FOUND) $(ARGV)"; \
		exit 1;                                                     \
	fi
#
#	Checking between raddb/mods-config/tftp/$file & build/test/tftp/$file
#
	$(Q)if ! scripts/md5filecheck.sh $(FOUND) $(EXPECTED); then  \
		echo "TFTPLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "TFTPLIENT: $(TFTPLIENT) -H localhost -p $(PORT) -q -D $(FILE) -o $(FOUND) $(ARGV)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the proto_tftp code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                    \
		diff $(EXPECTED) $(FOUND);                                  \
		rm -f $(BUILD_DIR)/tests/test.tftp;                       \
		$(MAKE) --no-print-directory test.tftp.radiusd_kill;      \
		exit 1;                                                     \
	fi
	$(Q)touch $@

$(TEST):
	$(Q)$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@

else
.PHONY: test.tftp
test.tftp:
	$(Q)echo "WARNING: 'tests.tftp' requires 'tftpy' Python3 module. e.g: pip3 install tftpy"
	$(Q)echo "Skipping 'test.tftp'"
endif
