#
#  Track inter-test dependencies.
#
#  This file MUST be included last from the "all.mk" file in this
#  directory.  Otherwise the macros for the individual tests aren't
#  defined.
#

#
#  bin, trie, and dict tests can run in parallel.
#

$(FILES.test.unit): $(FILES.test.dict)

$(FILES.test.xlat): $(FILES.test.unit)

$(FILES.test.keywords): $(FILES.test.trie) $(FILES.test.unit) | build.raddb

$(FILES.test.modules): $(FILES.test.keywords)

$(FILES.test.auth): $(FILES.test.keywords)

$(FILES.test.radsniff): $(FILES.test.unit)

$(FILES.test.process): $(FILES.test.keywords)

#
#  All of the tests which run a RADIUS server need to be run in
#  series, so they all depend on each other
#
TEST_ALL_ORDER := radiusd-c radclient detail digest radmin eap vmps

ifneq "$(FILES.test.tacacs)" ""
TEST_ALL_ORDER += tacacs
endif

ifneq "$(FILES.test.ldap_sync)" ""
TEST_ALL_ORDER += ldap_sync
endif

TEST_ALL_PREV = process

#
#  Ensure that all of the "radiusd -C" tests are run in series.
#
#  At least until such time as they're either run in docker
#  containers, OR they're all run on different ports.
#
define TEST_ALL_DEPS
$$(FILES.test.${1}): $$(FILES.test.$(TEST_ALL_PREV))
TEST_ALL_PREV := ${1}
endef

$(foreach x,$(TEST_ALL_ORDER),$(eval $(call TEST_ALL_DEPS,$x)))

#
#  @todo - loop over all tests in each directory which runs radiusd-c,
#  serializing them, too.  See src/tests/modules/all.mk for examples.
#
