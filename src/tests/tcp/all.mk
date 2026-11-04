#
#  Tests for plain TCP proxy sockets.
#
#  Each scenario starts a home server that listens on TCP, starts radiusd as
#  a proxy to the home server, and sends UDP requests to radiusd.  See
#  run_test.py for what each scenario does.
#
TCP_SCENARIOS := reply refuse close stall slow-accept

#
#  Because $(DIR) changes before make runs a recipe, save a copy of $(DIR) in
#  TCP_DIR.
#
TCP_DIR := $(DIR)

.PHONY: tests.tcp

#
#  The tests need TCP support and Python.
#
ifneq "$(and $(AC_WITH_TCP),$(shell command -v python3))" ""

tests.tcp: $(addprefix $(BUILD_DIR)/tests/tcp/,$(TCP_SCENARIOS))

$(BUILD_DIR)/tests/tcp:
	${Q}mkdir -p $@

#
#  Run each scenario.  A passing scenario touches the stamp file of the
#  scenario.  Because make runs a scenario only when an input is newer than the
#  stamp file, `make tests.tcp` runs only the scenarios with changed inputs.
#  radiusd writes the output of each scenario to
#  $(BUILD_DIR)/tests/tcp/<scenario>.d/radiusd.log.
#
$(BUILD_DIR)/tests/tcp/%: $(TCP_DIR)/run_test.py $(TCP_DIR)/radius.py $(TCP_DIR)/home_server.py $(TCP_DIR)/client.py $(TCP_DIR)/radiusd.conf $(BUILD_DIR)/bin/radiusd | $(BUILD_DIR)/tests/tcp
	${Q}echo "TCP-TEST $(notdir $@)"
	${Q}python3 $(TCP_DIR)/run_test.py --radiusd "$(TESTBIN)/radiusd" --dictdir $(DICT_PATH) --conf-dir $(TCP_DIR) --out-dir $@.d $(notdir $@)
	${Q}touch $@

else

tests.tcp:
	@echo "TCP-TEST skipped, as TCP or python3 is not available"

endif

.PHONY: clean.tests.tcp
clean.tests.tcp:
	${Q}rm -rf $(BUILD_DIR)/tests/tcp

clean.test: clean.tests.tcp
