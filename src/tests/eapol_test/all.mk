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
EAPOL_OK_FILES	 := $(patsubst $(DIR)/%.conf,$(OUTPUT)/%.ok,$(EAPOL_TEST_FILES))

#
#  Add rules so that we can run individual tests for each EAP method.
#
define ADD_TEST_EAP
test.eap.${1}: $(OUTPUT)/${1}.ok
endef
$(foreach x,$(patsubst $(DIR)/%.conf,%,$(EAPOL_TEST_FILES)),$(eval $(call ADD_TEST_EAP,$x)))


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
#  We don't depend on server build artifacts when we are executing from the post-install test environment
#
$(OUTPUT)/%.ok: $(DIR)/%.conf $(if $(POST_INSTALL_MAKEFILE_ARG),,$(BUILD_DIR)/lib/libfreeradius-server.la $(BUILD_DIR)/lib/libfreeradius-util.la) | $(GENERATED_CERT_FILES)
	@echo "EAPOL-TEST $(notdir $(patsubst %.conf,%,$<))"
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.eap.radiusd_kill
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory METHOD=$(basename $(notdir $@)) test.eap.radiusd_start $(POST_INSTALL_RADIUSD_BIN_ARG)
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
		$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) test.eap.radiusd_kill;						\
		echo "RADIUSD :  OUTPUT=$(dir $@) TESTDIR=$(dir $<) METHOD=$(notdir $(patsubst %.conf,%,$<)) TEST_PORT=$(PORT) $(RADIUSD_BIN) -fxxx -n servers -d $(dir $<)config -D $(DICT_PATH) -lstdout -f";\
		echo "EAPOL   :  $(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET) $(KEY) "; \
		echo "           log is in $(OUT)"; \
		rm -f $(BUILD_DIR)/tests/test.eap;                                      \
		$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.eap.radiusd_kill;			\
		exit 1;\
	fi
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.eap.radiusd_stop
	${Q}touch $@

$(TEST): $(EAPOL_OK_FILES)
	@touch $(BUILD_DIR)/tests/$@

else
$(BUILD_DIR)/tests/eapol_test:
	@mkdir -p $@

$(TEST):
	@echo "eapol_test build previously failed, skipping... retry with: $(MAKE) clean.$@ && $(MAKE) $@"

.PHONY: clean.test.eap
clean.test.eap:
	${Q}rm -f $(BUILD_DIR)/tests/eapol_test
endif
