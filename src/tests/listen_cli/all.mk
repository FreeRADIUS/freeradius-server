#
#  Test "radiusd -i ADDRESS -p PORT".  The server opens an
#  authentication listener on PORT, and an accounting listener on
#  PORT + 1.  Both use the virtual server named by "-n", or else
#  "default".
#
LISTEN_CLI_DIR	:= $(DIR)
LISTEN_CLI_OUT	:= $(BUILD_DIR)/tests/listen_cli
LISTEN_CLI_PORT	:= 12350
LISTEN_CLI_RUN	:= sh $(LISTEN_CLI_DIR)/run.sh "$(TESTBIN)/radiusd" "$(TESTBIN)/radclient" $(LISTEN_CLI_DIR)/config $(DICT_PATH)

LISTEN_CLI_DEPS	:= $(LISTEN_CLI_DIR)/run.sh $(wildcard $(LISTEN_CLI_DIR)/*.txt $(LISTEN_CLI_DIR)/config/*.conf) $(TESTBINDIR)/radiusd $(TESTBINDIR)/radclient

.PHONY: tests.listen_cli
tests.listen_cli: $(LISTEN_CLI_OUT)/default $(LISTEN_CLI_OUT)/other

#
#  No "-n": the listeners use "default".
#
$(LISTEN_CLI_OUT)/default: $(LISTEN_CLI_DEPS)
	${Q}echo "LISTEN-CLI-TEST default"
	${Q}$(LISTEN_CLI_RUN) $@.d $(LISTEN_CLI_PORT) default
	${Q}touch $@

#
#  "-n other": the listeners use "other".
#
$(LISTEN_CLI_OUT)/other: $(LISTEN_CLI_DEPS) | $(LISTEN_CLI_OUT)/default
	${Q}echo "LISTEN-CLI-TEST other"
	${Q}$(LISTEN_CLI_RUN) $@.d $(LISTEN_CLI_PORT) other other
	${Q}touch $@

.PHONY: clean.tests.listen_cli
clean.tests.listen_cli:
	${Q}rm -rf $(LISTEN_CLI_OUT)

clean.test: clean.tests.listen_cli
