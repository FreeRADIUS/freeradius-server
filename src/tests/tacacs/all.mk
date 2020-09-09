TACACS_BUILD_DIR  := $(BUILD_DIR)/tests/tacacs

#
#	We need the 'tacacs_plus' Python3 module to excute TACACS+ tests
#	i.e: Needed by ./scripts/tacacs/tacacs_client
#
$(TACACS_BUILD_DIR)/depends.mk:
	@mkdir -p $(dir $@)
	@(python3 -c "import tacacs_plus" 2>&- && echo WITH_TACACS=yes || echo WITH_TACACS=no) > $@

-include $(TACACS_BUILD_DIR)/depends.mk



#
#	Unit tests for scripts/tacacs/tacacs_client against the radiusd/proto_tacacs.
#
ifeq "$(WITH_TACACS)" "yes"
#
#	Test name
#
TEST  := test.tacacs
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
TACACS_BUILD_DIR  := $(BUILD_DIR)/tests/tacacs
TACACS_RADIUS_LOG := $(TACACS_BUILD_DIR)/radiusd.log
TACACS_GDB_LOG    := $(TACACS_BUILD_DIR)/gdb.log

#
#	Local TACACS+ client
#
TACCLIENT := scripts/tacacs/tacacs_client

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

#
#	Run the tacacs_client commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(Q)echo "PROTO_TACACS INPUT=$(TARGET) TACACS_ARGV=\"$(ARGV)\""
	$(Q)[ -f $(dir $@)/radiusd.pid ] || exit 1
	$(Q)if ! $(TACCLIENT) --return-0-if-failed -v -k $(SECRET) -p $(PORT) -H localhost -r 192.168.69.1 -P pegapilha/0 --timeout 2 $(ARGV) 1> $(FOUND) 2>&1; then \
		echo "FAILED";                                              \
		cat $(FOUND);                                               \
		rm -f $(BUILD_DIR)/tests/test.tacacs;                       \
		$(MAKE) --no-print-directory test.tacacs.radiusd_kill;      \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "TACCLIENT: $(TACCLIENT) --return-0-if-failed -v -k $(SECRET) -p $(PORT) -H localhost -r 192.168.69.1 -P pegapilha/0 --timeout 2 $(ARGV)"; \
		exit 1;                                                     \
	fi
#
#	Checking.
#
#	1. diff between src/test/tacacs/$test.out & build/test/tacacs/$test.out
#
	$(Q)if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then  \
		echo "TACCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "TACCLIENT: $(TACCLIENT) --return-0-if-failed -v -k $(SECRET) -p $(PORT) -H localhost -r 192.168.69.1 -P pegapilha/0 --timeout 2 $(ARGV)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the proto_tacacs code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                    \
		diff $(EXPECTED) $(FOUND);                                  \
		rm -f $(BUILD_DIR)/tests/test.tacacs;                       \
		$(MAKE) --no-print-directory test.tacacs.radiusd_kill;      \
		exit 1;                                                     \
	fi
	$(Q)touch $@

$(TEST):
	$(Q)$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@

else
.PHONY: test.tacacs
test.tacacs:
	$(Q)echo "WARNING: 'tests.tacacs' requires 'tacacs_plus' Python3 module. e.g: pip3 install tacacs_plus"
	$(@)echo "Skipping 'test.tacacs'"
endif
