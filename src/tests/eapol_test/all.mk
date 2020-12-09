#
#  The "build eapol_test" makefile contains only a definition of
#  EAPOL_TEST, which is where the binary is located.
#
#  But, we only try to build eapol_test if we're building _any_ tests.
#
#  If we're not running tests, OR if EAPOL_TEST isn't defined, then we
#  skip the rest of these tests.
#
ifneq "$(findstring test,$(MAKECMDGOALS))" ""
$(BUILD_DIR)/tests/eapol_test:
	@mkdir -p $@

# define where the EAPOL_TEST is located.  If necessary, build it.
$(BUILD_DIR)/tests/eapol_test/eapol_test.mk: | $(BUILD_DIR)/tests/eapol_test
	${Q}echo "EAPOL_TEST=" $(shell $(top_srcdir)/scripts/ci/eapol_test-build.sh) > $@

# include the above definition.  If the "mk" file doesn't exist, then the preceding
# rule will cause it to be build.
-include $(BUILD_DIR)/tests/eapol_test/eapol_test.mk

#  A helpful target which causes eapol_test to be built, BUT does not run the
#  "test.eap" targets.
.PHONY:
eapol_test:
	@echo EAPOL_TEST=$(EAPOL_TEST)
endif

#
#	Tests for EAP support
#
TEST := test.eap

ifneq "$(EAPOL_TEST)" ""
$(eval $(call TEST_BOOTSTRAP))

TEST_PATH := ${top_srcdir}/src/tests/eapol_test
CONFIG_PATH := $(TEST_PATH)/config
RADIUS_LOG := $(OUTPUT)/radiusd.log
GDB_LOG := $(OUTPUT)/gdb.log
TEST_BIN := $(BUILD_DIR)/bin/local

#
#   We use the stock raddb modules to help detect typos and other issues
#
RADDB_PATH := $(top_builddir)/raddb

#
#	Disabled modules.
#
IGNORED_EAP_TYPES := peap ttls

#
#   This ensures that FreeRADIUS uses modules from the build directory
#
EAP_TARGETS      := $(filter rlm_eap_%,$(ALL_TGTS))
EAP_TYPES_LIST   := $(patsubst rlm_eap_%.la,%,$(EAP_TARGETS))
EAP_TYPES        := $(filter-out $(IGNORED_EAP_TYPES),$(EAP_TYPES_LIST))
EAPOL_TEST_FILES := $(foreach x,$(EAP_TYPES),$(wildcard $(DIR)/$(x)*.conf))
EAPOL_OK_FILES  := $(patsubst $(DIR)/%.conf,$(OUTPUT)/%.ok,$(EAPOL_TEST_FILES))

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,servers,$(OUTPUT)))

#
#	Print the disabled list.
#
$(IGNORED_EAP_TYPES):
	@echo "EAPOL-TEST $@ - Disabled.  Enable by removing '$@' from 'IGNORED_EAP_TYPES' in src/tests/eapol_test/all.mk"

#
#  Separate the dependencies here just to keep a bit clear.
#
test.eap.check: $(IGNORED_EAP_TYPES) | $(OUTPUT) $(GENERATED_CERT_FILES)

#
#  Run EAP tests.
#
$(OUTPUT)/%.ok: $(DIR)/%.conf | $(GENERATED_CERT_FILES)
	@echo "EAPOL-TEST $(notdir $(patsubst %.conf,%,$<))"
	${Q}$(MAKE) --no-print-directory test.eap.radiusd_kill
	${Q}$(MAKE) --no-print-directory METHOD=$(basename $(notdir $@)) test.eap.radiusd_start
	${Q} [ -f $(dir $@)/radiusd.pid ] || exit 1
	$(eval OUT := $(patsubst %.ok,%.log,$@))
	$(eval KEY := $(shell grep key_mgmt=NONE $< | sed 's/key_mgmt=NONE/-n/'))
	${Q}if ! $(EAPOL_TEST) -t 2 -c $< -p $(PORT) -s $(SECRET) $(KEY) > $(OUT) 2>&1; then	\
		echo "Last entries in supplicant log ($(patsubst %.conf,%.log,$@)):";	\
		tail -n 40 "$(patsubst %.conf,%.log,$@)";				\
		echo "--------------------------------------------------";		\
		tail -n 40 "$(RADIUS_LOG)";						\
		echo "Last entries in server log ($(RADIUS_LOG)):";			\
		echo "--------------------------------------------------";		\
		echo "$(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET)";			\
		$(MAKE) test.eap.radiusd_kill;						\
		echo "RADIUSD :  OUTPUT=$(dir $@) TESTDIR=$(dir $<) METHOD=$(notdir $(patsubst %.conf,%,$<)) TEST_PORT=$(PORT) $(RADIUSD_BIN) -Pxxx -n servers -d $(dir $<)config -D share/dictionary/ -lstdout -f";\
		echo "EAPOL   :  $(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET) $(KEY) "; \
		echo "           log is in $(OUT)"; \
		rm -f $(BUILD_DIR)/tests/test.eap;                                      \
		$(MAKE) --no-print-directory test.eap.radiusd_kill;			\
		exit 1;\
	fi
	${Q}$(MAKE) --no-print-directory test.eap.radiusd_stop
	${Q}touch $@

$(TEST): $(EAPOL_OK_FILES)
	@touch $(BUILD_DIR)/tests/$@

else
$(TEST):
	@echo "eapol_test build previously failed, skipping... retry with: $(MAKE) clean.$@ && $(MAKE) $@"

.PHONY: clean.test.eap
clean.test.eap:
	${Q}rm -f $(BUILD_DIR)/tests/eapol_test
endif
