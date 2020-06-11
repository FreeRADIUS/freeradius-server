#
#  Test name
#
TEST := test.modules

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(sort $(patsubst $(DIR)/%.unlang,%,$(wildcard $(DIR)/*/*unlang)))

#
#  Remove things which are known to fail on travis.
#
ifeq "$(TRAVIS)" "1"
MODULES_SKIP := $(filter icmp,$(FILES))
endif

#
#  Figure out what to do with the module.
#
define MODULE_FILTER
ifneq "$(findstring rlm_${1}.la,$(ALL_TGTS))" "rlm_${1}.la"
  # the library isn't built, skip the module.
  MODULES_SKIP += ${2}

else ifeq "$(wildcard src/tests/modules/${1}/all.mk)" ""
  # there's no "all.mk" file, skip the module
  MODULES_SKIP += ${2}

else
  # the output file depends on the library, too.
  $(BUILD_DIR)/tests/modules/${2}.out: rlm_${1}.la

  -include src/tests/modules/${1}/all.mk

  ifdef ${1}_require_test_server
    ifdef TEST_SERVER
      # define FOO_TEST_SERVER
      $(eval $(shell echo ${1} | tr a-z A-Z)_TEST_SERVER := $(TEST_SERVER))
    else
      # the module requires a test server, but we don't have one.  Skip it.
      MODULES_SKIP += ${2}
    endif
  endif
endif
endef

#
#  Ensure that "rlm_foo.a" is built when we run a module from directory "foo"
#
$(foreach x,$(FILES),$(eval $(call MODULE_FILTER,$(firstword $(subst /, ,$x)),$x)))
$(info $(MODULES_SKIP))
FILES := $(filter-out $(MODULES_SKIP),$(FILES))
$(eval $(call TEST_BOOTSTRAP))


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
$(OUTPUT)/%: $(DIR)/%.unlang $(TEST_BIN_DIR)/unit_test_module | build.raddb
	@echo "MODULE-TEST $(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))"
	${Q}mkdir -p $(dir $@)
	${Q}cp $(if $(wildcard $(basename $<).attrs),$(basename $<).attrs,src/tests/modules/default-input.attrs) $@.attrs
	${Q}if ! MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i "$@.attrs" -f "$@.attrs" -r "$@" -xxx > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat "$@.log"; \
			echo "# $@.log"; \
			echo "MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xx"; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat "$@.log"; \
			echo "# $@.log"; \
			echo "MODULE_TEST_DIR=$(dir $<) MODULE_TEST_UNLANG=$< $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/modules/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xx"; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	fi


$(TEST):
	@touch $(BUILD_DIR)/tests/$@
