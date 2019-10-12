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
$(eval $(call RADIUSD_SERVICE,control-socket,$(OUTPUT)))

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
$(OUTPUT)/depends.mk: $(FILES) | $(OUTPUT)
	${Q}rm -f $@
	${Q}touch $@
	${Q}for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(BUILD_DIR)/tests/radmin/,g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$${z}: $${y}.txt" >> $@; \
			echo "" >> $@; \
		fi \
	done
-include $(OUTPUT)/depends.mk

#
#	Run the radmin commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% ${BUILD_DIR}/bin/radmin test.radmin.radiusd_kill test.radmin.radiusd_start
	${Q} [ -f $(dir $@)/radiusd.pid ] || exit 1
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval TARGET   := $(patsubst %.txt,%,$(notdir $@)))
	${Q}echo "RADMIN-TEST $(TARGET)"; \
	if ! $(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND); then\
		echo "--------------------------------------------------"; \
		tail -n 20 "$(RADMIN_RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADMIN_RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "RADIUSD: $(RADIUSD_RUN)"; \
		echo "RADMIN : $(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND)"; \
		$(MAKE) test.radmin.radiusd_kill; \
		exit 1; \
	fi; \
	if ! cmp -s $(FOUND) $(EXPECTED); then \
		echo "RADMIN FAILED $@"; \
		echo "RADIUSD: $(RADIUSD_RUN)"; \
		echo "RADMIN : $(RADMIN_BIN) -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the radmin code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)"; \
		diff $(EXPECTED) $(FOUND); \
		$(MAKE) test.radmin.radiusd_kill; \
		exit 1; \
	else \
		touch $@;\
	fi

$(TEST): $(FILES)
	${Q}$(MAKE) test.radmin.radiusd_kill
