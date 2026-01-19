#
#  Test name
#
TEST := test.modules

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(patsubst $(DIR)/%.unlang,%,$(call FIND_FILES_SUFFIX,$(DIR),*.unlang))
FILES_SKIP :=

#
#  Don't run icmp tests on Linux, they require setcap, or root.
#  @todo - on Linux, *check* for root, or use "getcap" to see if the
#  unit_test_module binary has the correct permissions.
#
ifeq "$(findstring apple,$(AC_HOSTINFO))" ""
  FILES_SKIP += $(filter icmp/%,$(FILES))
else
  FILES_SKIP += $(filter unbound/%,$(FILES))
endif

#
#  Test of rlm_otp use oathtool - not installed on MacOS or FreeBSD
#
ifeq "$(findstring linux,$(AC_HOSTINFO))" ""
  FILES_SKIP += $(filter totp/%,$(FILES))
endif

#
#  Remove tests which are known to be slow, unless we want them to be run.
#
ifneq "$(RUN_SLOW_TESTS)" "1"
  FILES_SKIP += $(filter imap/%,$(FILES))
endif

#
#  Don't run crl or dpsk tests if there's no SSL
#
ifeq "$(OPENSSL_LIBS)" ""
  FILES_SKIP += $(filter crl/%,$(FILES))
  FILES_SKIP += $(filter dpsk/%,$(FILES))
endif

#
#  Figure out what to do with the module.
#
define MODULE_FILTER
ifneq "$(findstring rlm_${1}.la,$(ALL_TGTS))" "rlm_${1}.la"
  # the library isn't built, skip the module.
  FILES_SKIP += ${2}

else ifeq "$(wildcard src/tests/modules/${1}/all.mk)" ""
  # there's no "all.mk" file, skip the module
  FILES_SKIP += ${2}

else
  -include src/tests/modules/${1}/all.mk

  ifdef ${1}_require_test_server
    ifdef TEST_SERVER
      # define and export FOO_TEST_SERVER if it's not already defined
      $(eval export $(toupper ${1})_TEST_SERVER ?= $(TEST_SERVER))
    endif
    ifeq "$($(toupper ${1})_TEST_SERVER)" ""
      # the module requires a test server, but we don't have one.  Skip it.
      FILES_SKIP += ${2}
    endif
  endif
endif
endef

######################################################################
#
#  Ensure that tests in one directory run in sequence.
#
#  If the magic macro is set: TEST.modules.foo.parallel=1
#  then the tests in that directory can be run in parallel.
#
#  Each "foo/all.mk" file contains a horrible GNU Make thing which
#  automatically uses the correct name.  This is so that we can just
#  copy the macro to a new file, and don't have to edit it for each
#  directory.
#
#  If there's no macro defined for this subdirectory, then define it
#  to be the current test.
#
#  Otherwise, make the current test depend on the previous one.
#  Then redefine the macro to be the current test.
#
#  This creates a "chain" of dependencies for all tests in a
#  subdirectory, so that they run in series.
#
#  We only do this if the module is explicitly marked as can
#  parallelize.
#
#  Use $(eval $(call TEST_MODULES_DEPS))
#
######################################################################
define TEST_MODULES_DEPS
ifneq "$(TEST.modules.$(subst /,,$(dir $1)).parallel)" ""
ifeq "$(OUTPUT.modules.$(dir $1))" ""
OUTPUT.modules.$(dir $1) := $(OUTPUT)/$1
else
$(OUTPUT.modules.$(dir $1)): $(OUTPUT)/$1
OUTPUT.modules.$(dir $1) := $(OUTPUT)/$1
endif
endif
endef

#
#  Ensure that "rlm_foo.a" is built when we run a module from directory "foo"
#
$(foreach x,$(FILES),$(eval $(call MODULE_FILTER,$(firstword $(subst /, ,$x)),$x)))
FILES := $(filter-out $(FILES_SKIP),$(FILES))
$(eval $(call TEST_BOOTSTRAP))

$(foreach x,$(FILES),$(eval $(call TEST_MODULES_DEPS,$x)))


#
#  For each output file, find the rlm_*.la module which it needs,
#  and make the output file depend on the library.  That way if the
#  module is re-built, then the tests are re-run.
#
$(foreach x, $(FILES), $(eval $$(OUTPUT.$(TEST))/$x: $(patsubst %,$(BUILD_DIR)/lib/rlm_%.la,$(patsubst %/,%,$(firstword $(subst /, ,$(dir $x))))) $(patsubst %,$(BUILD_DIR)/lib/local/rlm_%.la,$(patsubst %/,%,$(firstword $(subst /, ,$(dir $x)))))))

#
#  sql_foo depends on rlm_sql, too.
#
$(foreach x, $(filter sql_%,$(FILES)), $(eval $$(OUTPUT.$(TEST))/$x: $(BUILD_DIR)/lib/local/rlm_sql.la))

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/modules/*/FOO.unlang	unlang for the test
#	src/tests/modules/*/FOO.attrs	input RADIUS and output filter
#	build/tests/modules/*/FOO.out	updated if the test succeeds
#	build/tests/modules/*/FOO.log	debug output for the test
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(OUTPUT)/%: TEST=$(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))

$(OUTPUT)/%: $(DIR)/%.unlang $(TEST_BIN_DIR)/unit_test_module | build.raddb
	@echo "MODULE-TEST $(TEST)"
	${Q}mkdir -p $(dir $@)
	${Q}cp $(if $(wildcard $(basename $<).attrs),$(basename $<).attrs,src/tests/modules/default-input.attrs) $@.attrs
	${Q}if ! MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< TEST="$(TEST)" OUTPUT_DIR=$(dir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i "$@.attrs" -f "$@.attrs" -r "$@" -xxx > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			if grep 'LeakSanitizer has encountered a fatal error' $@.log 2>&1 > /dev/null; then \
				echo "MODULE-TEST $(TEST) - ignoring LeakSanitizer fatal error."; \
				exit 0; \
			fi; \
			cat "$@.log"; \
			echo "# $@.log"; \
			echo "MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< OUTPUT_DIR=$(dir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xx"; \
			exit 1; \
		fi; \
		FOUND=$$(grep -E 'Error : $<' $@.log | head -1 | sed 's/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat "$@.log"; \
			echo "# $@.log"; \
			echo "MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< OUTPUT_DIR=$(dir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xx"; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	fi

#
#  Allow running individual tests.
#
define UNIT_TEST_MODULES
$(TEST).help: HELP+=$(TEST).${1}

$(TEST).${1}: $(addprefix $(OUTPUT)/,$(filter ${1}/%,$(FILES)))
endef
$(foreach x,$(subst /,,$(sort $(dir $(FILES)))),$(eval $(call UNIT_TEST_MODULES,$x)))

.PHONY: $(TEST).help
$(TEST).help:
	@echo $(HELP)

$(TEST):
	@touch $(BUILD_DIR)/tests/$@

#
#  Create the certs directory
#
$(DIR)/certs: $(top_srcdir)/raddb/certs
	@ln -s $< $@
