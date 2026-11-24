#
#  Test that the server frees the session-state of sessions which
#  are still pending when it exits.
#
SESSION_STATE_DIR	:= $(DIR)
SESSION_STATE_OUT	:= $(BUILD_DIR)/tests/session_state
SESSION_STATE_PORT	:= 12365

SESSION_STATE_DEPS	:= $(SESSION_STATE_DIR)/run.sh $(SESSION_STATE_DIR)/auth.txt $(SESSION_STATE_DIR)/config/radiusd.conf $(TESTBINDIR)/radiusd $(TESTBINDIR)/radclient

.PHONY: tests.session_state
tests.session_state: $(SESSION_STATE_OUT)/pending

$(SESSION_STATE_OUT)/pending: $(SESSION_STATE_DEPS)
	${Q}echo "SESSION-STATE-TEST pending"
	${Q}sh $(SESSION_STATE_DIR)/run.sh "$(TESTBIN)/radiusd" "$(TESTBIN)/radclient" $(SESSION_STATE_DIR)/config $(DICT_PATH) $@.d $(SESSION_STATE_PORT)
	${Q}touch $@

.PHONY: clean.tests.session_state
clean.tests.session_state:
	${Q}rm -rf $(SESSION_STATE_OUT)

clean.test: clean.tests.session_state
