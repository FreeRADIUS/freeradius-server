#
#	Unit tests for radmin tool against the radiusd.
#

#
#	Test name
#
TEST := test.radmin

#
#  The test files are files without extensions.
#
FILES  := $(subst $(DIR)/%,,$(wildcard $(DIR)/*.txt))
OUTPUT := $(subst $(top_srcdir)/src,$(BUILD_DIR),$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

#
#	Config settings
#
RADMIN_BIN         := $(TESTBINDIR)/radmin
RADMIN_RADIUS_LOG  := $(OUTPUT)/radius.log
RADMIN_GDB_LOG     := $(OUTPUT)/gdb.log
RADMIN_SOCKET_FILE := $(OUTPUT)/control-socket.sock
RADMIN_CONFIG_PATH := $(DIR)/config

include src/tests/radiusd.mk
PORT := 12340
$(eval $(call RADIUSD_SERVICE,control-socket))
#
#  Create the output directory
#
.PHONY: $(OUTPUT)
$(OUTPUT):
	${Q}mkdir -p $@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $(OUTPUT),$(notdir $(FILES)))

#
#  The output files also depend on the directory
#  and on the previous test.
#
$(FILES.$(TEST)): | $(OUTPUT)

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $(FILES.$(TEST))
	${Q}touch $@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the output directory and files.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	${Q}rm -rf $(OUTPUT)

clean.test: clean.$(TEST)

#
#	Run the radmin commands against the radiusd.
#
$(BUILD_DIR)/tests/radmin/%: $(DIR)/% test.radmin.radiusd_kill test.radmin.radiusd_start
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval TARGET   := $(patsubst %.txt,%,$(notdir $@)))
	${Q}echo "RADMIN-TEST $(TARGET)"; \
	if ! $(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) > $(FOUND) < $<; then\
		echo "--------------------------------------------------"; \
		tail -n 20 "$(RADMIN_RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADMIN_RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "TEST_PORT=$(PORT) $(JLIBTOOL) --mode=execute $(BIN_PATH)/radiusd -PXxx -d \"$(RADMIN_CONFIG_PATH)\" -n control-socket -D \"${top_builddir}/share/dictionary/\""; \
		echo "$(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) > $(FOUND) < $<"; \
		$(MAKE) $(TEST).radiusd_kill; \
		exit 1;\
	fi; \
	if ! cmp -s $(FOUND) $(EXPECTED); then \
		echo "RADMIN FAILED $@"; \
		echo "ERROR: It is expected to $(FOUND) be same as $(EXPECTED)"; \
		echo "If you did some update on the Radmin code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)"; \
		diff $(FOUND) $(EXPECTED); \
		exit 1; \
	else \
		touch $@;\
	fi

$(TEST): $(FILES)
	${Q}$(MAKE) test.radmin.radiusd_kill

