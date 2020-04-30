#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.unit

#
#  Get all .txt files
#
FILES  := $(call FIND_FILES_SUFFIX,$(DIR),*.txt)

#
#  If we don't have OpenSSL, filter out tests which need TLS.
#
ifeq "$(AC_HAVE_OPENSSL_SSL_H)" ""
FILES := $(filter-out $(shell grep -l 'need-feature tls' $(FILES)),$(FILES))
endif

#
#  Remove our directory prefix, which is needed by the bootstrap function.
#
FILES := $(subst $(DIR)/,,$(FILES))

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more

#
#  Bootstrap the test framework.
#
$(eval $(call TEST_BOOTSTRAP))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#export ASAN_SYMBOLIZER_PATH=$(shell which llvm-symbolizer)
#export ASAN_OPTIONS=malloc_context_size=50 detect_leaks=1 symbolize=1
#export LSAN_OPTIONS=print_suppressions=0 fast_unwind_on_malloc=0

#
#  Look in each file for `proto foo`, and then make that file depend in `libfreeradius-foo.a`
#
DEPENDS_MK := $(OUTPUT)/depends.mk
$(OUTPUT)/depends.mk: $(addprefix $(DIR)/,$(FILES)) | $(OUTPUT)
	${Q}rm -f $@
	${Q}touch $@
	${Q}for x in $^; do \
		y=`grep '^proto ' $$x | sed 's/^proto //'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $(BUILD_DIR)/lib/libfreeradius-$$y.la" >> $@; \
			echo "" >> $@; \
		fi \
	done

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	$(eval DIR:=${top_srcdir}/src/tests/unit)
	@echo "UNIT-TEST $(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))"
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(DIR) -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(DIR) -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/test.unit; \
		exit 1; \
	fi
