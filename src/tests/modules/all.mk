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
