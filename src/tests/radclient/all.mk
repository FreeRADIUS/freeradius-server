#
#	Unit tests for radclient against the radiusd.
#

#
#	Test name
#
TEST  := test.radclient
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
RADCLIENT_BUILD_DIR  := $(BUILD_DIR)/tests/radclient
RADCLIENT_RADIUS_LOG := $(RADCLIENT_BUILD_DIR)/radiusd.log
RADCLIENT_GDB_LOG    := $(RADCLIENT_BUILD_DIR)/gdb.log

#
#	Client port
#
RADCLIENT_CLIENT_PORT = 1234

#
#  Generic rules to start / stop the radius service.
#
CLIENT := radclient
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,tapioca,$(OUTPUT)))

#
#	Run the radclient commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval TYPE     := $(shell echo $(TARGET) | cut -f1 -d '_'))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(Q)echo "RADCLIENT-TEST INPUT=$(TARGET) ARGV=\"$(ARGV)\""
	$(Q)[ -f $(dir $@)/radiusd.pid ] || exit 1
	$(Q)if ! $(TESTBIN)/radclient $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(PORT) $(TYPE) $(SECRET) 1> $(FOUND) 2>&1; then \
		echo "FAILED";                                              \
		cat $(FOUND);                                               \
		rm -f $(BUILD_DIR)/tests/test.radclient;		    \
		$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TESTBIN)/radclient $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -xF -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(PORT) $(TYPE) $(SECRET)"; \
		exit 1;                                                     \
	fi
#
#	Lets normalize the loopback interface on OSX
#
	$(Q)if [ "$$(uname -s)" = "Darwin" ]; then sed -i .bak 's/via lo0/via lo/g' $(FOUND); fi
#
#	Checking.
#
#	1. diff between src/test/radclient/$test.out & build/test/radclient/$test.out
#	or
#	2. call the script src/test/radclient/$test.cmd to validate the build/test/radclient/$test.out
#
	$(Q)if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then  \
		echo "RADCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TESTBIN)/radclient $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(PORT) $(TYPE) $(SECRET)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the radclient code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                    \
		diff $(EXPECTED) $(FOUND);                                  \
		rm -f $(BUILD_DIR)/tests/test.radclient;		    \
		$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
		exit 1;                                                     \
	elif [ -e "$(CMD_TEST)" ] && ! $(SHELL) $(CMD_TEST); then           \
		echo "RADCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TESTBIN)/radclient $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(PORT) $(TYPE) $(SECRET)"; \
		echo "ERROR: The script $(CMD_TEST) can't validate the content of $(FOUND)"; \
		echo "If you did some update on the radclient code, please be sure to update the unit tests."; \
		rm -f $(BUILD_DIR)/tests/test.radclient;		    \
		$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
		exit 1;                                                     \
	fi
	$(Q)touch $@

$(TEST):
	$(Q)$(MAKE) --no-print-directory $@.radiusd_kill
	@touch $(BUILD_DIR)/tests/$@
