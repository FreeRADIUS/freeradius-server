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
#  For the remaining ones, add on the directory to include.
#
SUBMAKEFILES := $(addsuffix /all.mk,$(TEST_BUILT))

#
#  Ensure that the tests depend on the module, so that changes to the
#  module will re-run the test
#
$(foreach x,$(TEST_BUILT),$(eval $x.test: rlm_$x.la))

#
#  Add the module tests to the overall dependencies
#
tests.modules: tests.unit tests.keywords tests.auth $(patsubst %,%.test,$(TEST_BUILT))
