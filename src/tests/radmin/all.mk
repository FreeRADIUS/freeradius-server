#
#	Unit tests for radmin tool against the radiusd.
#

#
#	Test name
#
TEST := test.radmin
FILES  := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

#
#  @todo - have a way to do this a bit more programmatically.
#
ifeq "$(AC_HAVE_GPERFTOOLS_PROFILER_H)" ""
FILES := $(filter-out set-profile-status-yes.txt show-profile-status.txt,$(FILES))
endif

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
RADMIN_RADIUS_LOG  := $(OUTPUT)/radiusd.log
RADMIN_GDB_LOG     := $(OUTPUT)/gdb.log
RADMIN_SOCKET_FILE := $(OUTPUT)/control-socket.sock
RADMIN_CONFIG_PATH := $(DIR)/config

#
#  Generic rules to start / stop the radius service.
#
CLIENT := radmin
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,control-socket,$(OUTPUT)))

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
$(OUTPUT)/depends.mk: $(addprefix $(DIR)/,$(FILES)) | $(OUTPUT)
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
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	@echo "RADMIN-TEST $(notdir $@)"
	${Q} [ -f $(dir $@)/radiusd.pid ] || exit 1
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval TARGET   := $(patsubst %.txt,%,$(notdir $@)))
	${Q}if ! $(TEST_BIN)/radmin -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND) 2>&1; then\
		echo "--------------------------------------------------"; \
		tail -n 20 "$(RADMIN_RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADMIN_RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "RADIUSD: $(RADIUSD_RUN)"; \
		echo "RADMIN : $(TEST_BIN)/radmin -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND)"; \
		rm -f $(BUILD_DIR)/tests/test.radmin; \
		$(MAKE) --no-print-directory test.radmin.radiusd_kill; \
		exit 1; \
	fi; \
	if ! cmp -s $(FOUND) $(EXPECTED); then \
		echo "RADMIN FAILED $@"; \
		echo "RADIUSD: $(RADIUSD_RUN)"; \
		echo "RADMIN : $(TEST_BIN)/radmin -q -f $(RADMIN_SOCKET_FILE) < $< > $(FOUND)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the radmin code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)"; \
		diff $(EXPECTED) $(FOUND); \
		rm -f $(BUILD_DIR)/tests/test.radmin; \
		$(MAKE) --no-print-directory test.radmin.radiusd_kill; \
		exit 1; \
	else \
		touch $@;\
	fi

$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
