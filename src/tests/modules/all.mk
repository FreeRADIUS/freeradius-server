#
#  Find the subdirs which have "all.mk"
#
TEST_SUBDIRS := $(patsubst src/tests/modules/%/all.mk,%,$(wildcard src/tests/modules/*/all.mk))

#
#  Find out which of those have a similar target.  i.e. modules/foo -> rlm_foo.la
#
TEST_TARGETS := $(foreach x,$(TEST_SUBDIRS),$(findstring rlm_$x.la,$(ALL_TGTS)))

TEST_BUILT := $(patsubst rlm_%.la,%,$(TEST_TARGETS))

#
#  Ensure that the tests depend on the module, so that changes to the
#  module will re-run the test
#
$(foreach x,$(TEST_BUILT),$(eval $x.test: rlm_$x.la))

######################################################################

#
#  And do the same thing for sub-directories
#
TEST_SUBSUBDIRS := $(patsubst src/tests/modules/%/all.mk,%,$(wildcard src/tests/modules/*/*/all.mk))

TEST_SUBTARGETS := $(foreach x,$(TEST_SUBSUBDIRS),$(findstring rlm_$(subst /,_,$x).la,$(ALL_TGTS)))

TEST_SUBBUILT := $(patsubst rlm_%.la,%,$(TEST_SUBTARGETS))

$(foreach x,$(TEST_SUBBUILT),$(eval $x.test: rlm_$(subst /,_,$x).la))

######################################################################
#
#  For the remaining subdirs, add on the directory to include.
#
SUBMAKEFILES := $(addsuffix /all.mk,$(TEST_BUILT) $(subst _,/,$(TEST_SUBBUILT)))

#
#  Add the module tests to the overall dependencies
#
tests.modules: tests.unit tests.keywords tests.auth $(patsubst %,%.test,$(TEST_BUILT) $(TEST_SUBBUILT))

######################################################################
#
#  And now more makefile magic to automatically run the tests
#  for each module.
#

define DEFAULT_ATTRS
ifeq "$(wildcard ${1}.attrs)"
${1}.attrs
else
src/tests/modules/default-input.attrs
endif
endef

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/$(MODULE_DIR)/FOO.unlang	unlang for the test
#	src/tests/$(MODULE_DIR)/FOO.attrs	input RADIUS and output filter
#	build/tests/$(MODULE_DIR)/FOO.out	updated if the test succeeds
#	build/tests/$(MODULE_DIR)/FOO.log	debug output for the test
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(BUILD_DIR)/tests/modules/%: src/tests/modules/%.unlang $(BUILD_DIR)/tests/modules/%.attrs $(TESTBINDIR)/unittest | build.raddb
	@mkdir -p $(dir $@)
	@echo MODULE-TEST $(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))
	@if ! MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx > $@.log 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi \
	fi
	@touch $@

#
#  Sometimes we have a default input.  So use that.  Otherwise, use
#  the input specific to the test.
#
MODULE_UNLANG		:= $(wildcard src/tests/modules/*/*.unlang src/tests/modules/*/*/*.unlang)
MODULE_ATTRS_REQUIRES	:= $(patsubst %.unlang,%.attrs,$(MODULE_UNLANG))
MODULE_ATTRS_EXISTS	:= $(wildcard src/tests/modules/*/*.attrs src/tests/modules/*/*/*.attrs)
MODULE_ATTRS_NEEDS	:= $(filter-out $(MODULE_ATTRS_EXISTS),$(MODULE_ATTRS_REQUIRES))

MODULE_CONF_REQUIRES	:= $(patsubst %.unlang,%.conf,$(MODULE_UNLANG))
MODULE_CONF_EXISTS	:= $(wildcard src/tests/modules/*/*.conf src/tests/modules/*/*/*.attrs)
MODULE_CONF_NEEDS	:= $(filter-out $(MODULE_CONF_EXISTS),$(MODULE_CONF_REQUIRES))

#
#  The complete list of tests which are to be run
#
MODULE_TESTS		:= $(patsubst src/tests/modules/%/all.mk,%,$(wildcard src/tests/modules/*/all.mk))


#
#  Target-specific rules
#
define MODULE_COPY_FILE
$(BUILD_DIR)/${1}: src/${1}
	@mkdir -p $$@
	@cp $$< $$@

endef

#
#  Default rules
#
define MODULE_COPY_ATTR
$(BUILD_DIR)/${1}: src/tests/modules/default-input.attrs
	@mkdir -p $$@
	@cp $$< $$@
endef

#
#  FIXME: get this working
#
define MODULE_COPY_CONF
$(BUILD_DIR)/${1}: src/tests/modules/${2}/module.conf
	@mkdir -p $$@
	@cp $$< $$@
endef

define MODULE_FILE_TARGET
$(BUILD_DIR)/${1}: src/${1}.unlang $(BUILD_DIR)/${1}.attrs

endef

define MODULE_TEST_TARGET
${1}.test: $(patsubst %.unlang,%,$(subst src,$(BUILD_DIR),$(filter src/tests/modules/${1}/%,$(MODULE_UNLANG))))

endef

#
#  Create the rules from the list of input files
#
$(foreach x,$(MODULE_ATTRS_EXISTS),$(eval $(call MODULE_COPY_FILE,$(subst src/,,$x))))
$(foreach x,$(MODULE_CONF_EXISTS),$(eval $(call MODULE_COPY_FILE,$(subst src/,,$x))))

$(foreach x,$(MODULE_ATTRS_NEEDS),$(eval $(call MODULE_COPY_ATTR,$(subst src/,,$x))))
# FIXME: copy src/tests/modules/*/module.conf to the right place, too

$(foreach x,$(MODULE_UNLANG),$(eval $(call MODULE_FILE_TARGET,$(patsubst %.unlang,%,$(subst src/,,$x)))))
$(foreach x,$(MODULE_TESTS),$(eval $(call MODULE_TEST_TARGET,$x)))

.PHONY: clean.modules.test
clean.modules.test:
	@rm -rf $(BUILD_DIR)/tests/modules/
