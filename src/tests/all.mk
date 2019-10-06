#
#  The tests do a lot of rooting through files, which slows down non-test builds.
#
#  Therefore only include the test subdirectories if we're running the tests.
#  Or, if we're trying to clean things up.
#
ifneq "$(findstring test,$(MAKECMDGOALS))$(findstring clean,$(MAKECMDGOALS))" ""
SUBMAKEFILES := radmin/all.mk rbmonkey.mk eapol_test/all.mk dict/all.mk trie/all.mk unit/all.mk map/all.mk xlat/all.mk keywords/all.mk util/all.mk auth/all.mk modules/all.mk bin/all.mk daemon/all.mk
endif

#
#  Include all of the autoconf definitions into the Make variable space
#
-include $(BUILD_DIR)/tests/autoconf.h.mk

.PHONY: $(BUILD_DIR)/tests
$(BUILD_DIR)/tests:
	@mkdir -p $@

#
#  Pull all of the autoconf stuff into here.
#
$(BUILD_DIR)/tests/autoconf.h.mk: src/include/autoconf.h | $(BUILD_DIR)/tests
	${Q}grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@

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
.PHONY: $$(OUTPUT.$(TEST))
$$(OUTPUT.$(TEST)):
	$${Q}mkdir -p $$@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $$(OUTPUT.$(TEST))/,$(notdir $(FILES)))

#
#  The output files also depend on the directory
#  and on the previous test.
#
$$(FILES.$(TEST)): | $$(OUTPUT.$(TEST))

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

clean.test: clean.$(TEST)
endef
