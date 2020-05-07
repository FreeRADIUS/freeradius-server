#
#	Common test values
#

PORT := 12340
SECRET := testing123

#
#  To work around OpenSSL issues with travis.
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
	${Q}if ! ${TESTBIN}/radiusd -XCMd ./raddb -n debug -D ./share/dictionary -n test > $(BUILD_DIR)/tests/radiusd.config.log; then \
		rm -f raddb/test.conf; \
		cat $(BUILD_DIR)/tests/radiusd.config.log; \
		echo "fail"; \
		echo "${TESTBIN}/radiusd -XCMd ./raddb -n debug -D ./share/dictionary -n test"; \
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
test: ${BUILD_DIR}/bin/radiusd ${BUILD_DIR}/bin/radclient \
		test.bin	\
		test.trie	\
		test.dict	\
		test.misc	\
		test.unit	\
		test.keywords	\
		test.xlat	\
		test.map	\
		test.modules	\
		test.radiusd-c	\
		test.auth	\
		test.radclient	\
		test.digest	\
		test.radmin	\
		test.eap	\
		| build.raddb

clean: clean.test
.PHONY: clean.test

#  Tests specifically for Travis. We do a LOT more than just
#  the above tests
travis-test: raddb/test.conf test
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
OUTPUT.$(TEST) := $(patsubst %/,%,$(subst $(top_srcdir)/src,$(BUILD_DIR),$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))
OUTPUT := $$(OUTPUT.$(TEST))

#
#  Create the output directory
#
$$(OUTPUT.$(TEST)):
	$${Q}mkdir -p $$@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $$(OUTPUT.$(TEST))/,$(FILES))

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
