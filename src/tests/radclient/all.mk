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
RADCLIENT            ?= radclient
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
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

$(OUTPUT)/auth_proxy.txt: $(BUILD_DIR)/lib/local/rlm_radius.la

define RADCLIENT_TEST
test.radclient.$(basename ${1}): $(addprefix $(OUTPUT)/,${1})

test.radclient.help: TEST_RADCLIENT_HELP += test.radclient.$(basename ${1})
endef

$(foreach x,$(FILES),$(eval $(call RADCLIENT_TEST, $x)))

#
#	Run the radclient commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% $(BUILD_DIR)/bin/local/$(RADCLIENT) $(BUILD_DIR)/lib/local/proto_radius.la $(BUILD_DIR)/lib/local/rlm_radius.la | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<)$(E))
	$(eval TYPE     := $(shell echo $(TARGET) | cut -f1 -d '_'))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(eval IGNORE_ERROR := $(shell grep -q "#.*IGNORE_ERROR:.*1" $< && echo 1 || echo 0))
	$(eval RADCLIENT_CLIENT_PORT := $(shell echo $$(($(RADCLIENT_CLIENT_PORT)+1))))

	${Q}echo "RADCLIENT-TEST INPUT=$(TARGET) ARGV=\"$(ARGV)\""
	${Q}[ -f $(dir $@)/radiusd.pid ] || exit 1
	${Q}if ! $(TEST_BIN)/$(RADCLIENT) $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(radclient_port) $(TYPE) $(SECRET) 1> $(FOUND) 2>&1; then \
		if [ "$(IGNORE_ERROR)" != "1" ]; then                               \
			echo "FAILED";                                              \
			cat $(FOUND);                                               \
			rm -f $(BUILD_DIR)/tests/test.radclient;		    \
			$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
			echo "RADIUSD:   $(RADIUSD_RUN)";                           \
			echo "RADCLIENT: $(TEST_BIN)/$(RADCLIENT) $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -xF -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(radclient_port) $(TYPE) $(SECRET)"; \
			exit 1;                                                     \
		fi;                                                                 \
	fi
#
#	Lets normalize the loopback interface on OSX and FreeBSD
#
	${Q}if [ "$$(uname -s)" = "Darwin" ]; then sed -i.bak 's/via lo0/via lo/g' $(FOUND); fi
	${Q}if [ "$$(uname -s)" = "FreeBSD" ]; then sed -i.bak 's/via (null)/via lo/g' $(FOUND); fi
#
#	Remove all entries with "^_EXIT.*CALLED .*/"
#	It is necessary to match all builds with/without -DNDEBUG
#
	${Q}sed -i.bak '/^_EXIT.*CALLED .*/d' $(FOUND)
#
#	Ignore spurious output from jlibtool when VERBOSE=1
#
	${Q}sed -i.bak '$${/Executing: /d;}' $(FOUND)
#
#	Checking.
#
#	1. diff between src/test/radclient/$test.out & build/test/radclient/$test.out
#	or
#	2. call the script src/test/radclient/$test.cmd to validate the build/test/radclient/$test.out
#
	${Q}grep -v 'Message-Authenticator' $(FOUND) > $(FOUND).out
	${Q}mv $(FOUND).out $(FOUND)
	${Q}if [ -e "$(EXPECTED)" ] && ! diff -I 'Sent' -I 'Received' $(EXPECTED) $(FOUND); then \
		echo "RADCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TEST_BIN)/$(RADCLIENT) $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(radclient_port) $(TYPE) $(SECRET)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the radclient code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                    \
		diff -I 'Sent' -I 'Received' $(EXPECTED) $(FOUND);                                  \
		rm -f $(BUILD_DIR)/tests/test.radclient;		    \
		$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
		exit 1;                                                     \
	elif [ -e "$(CMD_TEST)" ] && ! $(SHELL) $(CMD_TEST); then           \
		echo "RADCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TEST_BIN)/$(RADCLIENT) $(ARGV) -C $(RADCLIENT_CLIENT_PORT) -f $< -d src/tests/radclient/config -D share/dictionary 127.0.0.1:$(radclient_port) $(TYPE) $(SECRET)"; \
		echo "ERROR: The script $(CMD_TEST) can't validate the content of $(FOUND)"; \
		echo "If you did some update on the radclient code, please be sure to update the unit tests."; \
		rm -f $(BUILD_DIR)/tests/test.radclient;		    \
		$(MAKE) --no-print-directory test.radclient.radiusd_kill;   \
		exit 1;                                                     \
	fi
	${Q}touch $@

.NO_PARALLEL: $(TEST)
$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@

$(TEST).help:
	@echo make $(TEST_RADCLIENT_HELP)
