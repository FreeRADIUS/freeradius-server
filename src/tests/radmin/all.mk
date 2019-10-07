#
#	Unit tests for radmin tool against the radiusd.
#

#
#	Test name
#
TEST := test.radmin
FILES  := $(subst $(DIR)/%,,$(wildcard $(DIR)/*.txt))
$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
RADMIN_BIN         := $(TESTBINDIR)/radmin
RADMIN_RADIUS_LOG  := $(OUTPUT)/radiusd.log
RADMIN_GDB_LOG     := $(OUTPUT)/gdb.log
RADMIN_SOCKET_FILE := $(OUTPUT)/control-socket.sock
RADMIN_CONFIG_PATH := $(DIR)/config

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
PORT := 12340
$(eval $(call RADIUSD_SERVICE,control-socket,$(OUTPUT)))

#
#	Run the radmin commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% test.radmin.radiusd_kill test.radmin.radiusd_start
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval TARGET   := $(patsubst %.txt,%,$(notdir $@)))
	${Q}echo "RADMIN-TEST $(TARGET)"; \
	if ! $(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) > $(FOUND) < $<; then\
		echo "--------------------------------------------------"; \
		tail -n 20 "$(RADMIN_RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADMIN_RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "$(RADIUSD_RUN)"; \
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

