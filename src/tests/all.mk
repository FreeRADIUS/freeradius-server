#
#	Common test values
#

PORT := $(if $(PORT),$(PORT),12340)
SECRET := $(if $(SECRET),$(SECRET),testing123)
DICT_PATH := $(top_srcdir)/share/dictionary

#
#	We need the 'git-lfs' installed to fetch some binary files.
#
GIT_HAS_LFS = $(shell git lfs 1> /dev/null 2>&1 && echo yes || echo no)

#
#  To work around OpenSSL issues encountered with old OpenSSL within CI.
#
raddb/test.conf:
	${Q}echo 'security {' >> $@
	${Q}echo '        allow_vulnerable_openssl = yes' >> $@
	${Q}echo '}' >> $@
	${Q}echo '$$INCLUDE radiusd.conf' >> $@

#
#  Run "radiusd -C", looking for errors.
#
# Only redirect STDOUT, which should contain details of why the test failed.
# Don't molest STDERR as this may be used to receive output from a debugger.
$(BUILD_DIR)/tests/radiusd-c:
	@printf "radiusd -C... "
	${Q}if ! ${TEST_BIN}/radiusd -XCMd ./raddb -n debug -D ./share/dictionary -n test > $(BUILD_DIR)/tests/radiusd.config.log; then \
		cat $(BUILD_DIR)/tests/radiusd.config.log; \
		echo "fail"; \
		echo "${TEST_BIN}/radiusd -XCMd ./raddb -n debug -D ./share/dictionary -n test"; \
		exit 1; \
	fi
	${Q}rm -f raddb/test.conf
	@echo "ok"
	${Q}touch $@

.PHONY: test.radiusd-c
test.radiusd-c: raddb/test.conf $(BUILD_DIR)/tests/radiusd-c ${BUILD_DIR}/bin/radiusd $(GENERATED_CERT_FILES) | $(BUILD_DIR)/tests build.raddb

#
#  The tests are manually ordered for now, as it's a PITA to fix all
#  of the dependencies.
#
test: \
		test.bin	\
		test.trie	\
		test.dict	\
		test.unit	\
		test.keywords	\
		test.xlat	\
		test.map	\
		test.modules	\
		test.radiusd-c	\
		test.radclient	\
		test.radsniff	\
		test.auth	\
		test.digest	\
		test.radmin	\
		test.eap	\
		test.tacacs	\
		test.vmps	\
		| build.raddb

clean: clean.test
.PHONY: clean.test

#  Tests specifically for CI. We do a LOT more than just
#  the above tests
ci-test: raddb/test.conf test
	${Q}FR_LIBRARY_PATH=${BUILD_DIR}/lib/local/.libs/ ${BUILD_DIR}/make/jlibtool --mode=execute ${BUILD_DIR}/bin/local/radiusd -xxxv -n test
	${Q}rm -f raddb/test.conf
	${Q}$(MAKE) install
	${Q}perl -p -i -e 's/allow_vulnerable_openssl = no/allow_vulnerable_openssl = yes/' ${raddbdir}/radiusd.conf
	${Q}${sbindir}/radiusd -XC

#
#  The tests do a lot of rooting through files, which slows down non-test builds.
#
#  Therefore only include the test subdirectories if we're running the tests.
#  Or, if we're trying to clean things up.
#
ifneq "$(findstring test,$(MAKECMDGOALS))$(findstring clean,$(MAKECMDGOALS))" ""

#
#  Add LSAN / ASAN options.  And shut them up on OSX, which has leaks in libc.
#
ifneq "$(findstring leak,$(CFLAGS))" ""
export ASAN_SYMBOLIZER_PATH=$(shell which llvm-symbolizer)
export ASAN_OPTIONS=malloc_context_size=50 detect_leaks=1 symbolize=1
ifneq "$(findstring apple,$(AC_HOSTINFO))" ""
export LSAN_OPTIONS=print_suppressions=0 fast_unwind_on_malloc=0 suppressions=${top_srcdir}/scripts/build/lsan_leaks_osx
else
export LSAN_OPTIONS=print_suppressions=0 fast_unwind_on_malloc=0
endif
endif

SUBMAKEFILES := rbmonkey.mk $(subst src/tests/,,$(wildcard src/tests/*/all.mk))
endif

.PHONY: $(BUILD_DIR)/tests
$(BUILD_DIR)/tests:
	${Q}mkdir -p $@

######################################################################
#
#  Generic rules to set up the tests
#
#  Use $(eval $(call TEST_BOOTSTRAP))
#
######################################################################
define TEST_BOOTSTRAP

#
#  The test files are files without extensions.
#
OUTPUT.$(TEST) := $(patsubst %/,%,$(subst src/,$(BUILD_DIR)/,$(call CANONICAL_PATH,$(DIR))))
OUTPUT := $$(OUTPUT.$(TEST))

#
#  Create the output directory
#
$$(OUTPUT.$(TEST)):
	$${Q}mkdir -p $$@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $$(OUTPUT.$(TEST))/,$(sort $(FILES)))

#
#  The output files also depend on the directory
#  and on the previous test.
#
$$(FILES.$(TEST)): | $$(OUTPUT.$(TEST))

#
#  Make sure that the output files depend on the input.
#  This way if the input file doesn't exist, we get a
#  build error.  Without this rule, the test target
#  would just get re-built every time, no matter what.
#
$(foreach x, $(FILES), $(eval $$(OUTPUT.$(TEST))/$x: $(DIR)/$x))

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $$(FILES.$(TEST))
	$${Q}touch $$@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the output directory and files.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	$${Q}rm -rf $$(OUTPUT.$(TEST))
	$${Q}rm -f $$(BUILD_DIR)/tests/$(TEST)

clean.test: clean.$(TEST)
endef
