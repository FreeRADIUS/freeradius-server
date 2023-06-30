SUBMAKEFILES := rbmonkey.mk unit/all.mk map/all.mk xlat/all.mk keywords/all.mk auth/all.mk modules/all.mk sql_nas_table/all.mk
PORT := 12340
SECRET := testing123
DICT_PATH := $(top_srcdir)/share

#
#  Pull all of the autoconf stuff into here.
#
$(BUILD_DIR)/tests/autoconf.h.mk: src/include/autoconf.h
	@grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@

#
#  Include all of the autoconf definitions into the Make variable space
#
-include $(BUILD_DIR)/tests/autoconf.h.mk

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
OUTPUT.$(TEST) := $(patsubst %/,%,$(subst $(top_srcdir)/src,$(BUILD_DIR),$(abspath $(DIR))))
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
