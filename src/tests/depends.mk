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

$(FILES.test.radiusd-c): $(FILES.test.process)

#
#  All of the tests which run a RADIUS server need to be run in
#  series, so they all depend on each other
#
TEST_ALL_ORDER := radclient detail digest radmin eap vmps

ifneq "$(FILES.test.tacacs)" ""
TEST_ALL_ORDER += tacacs
endif

ifneq "$(FILES.test.ldap_sync)" ""
TEST_ALL_ORDER += ldap_sync
endif

#
#  Walk through all files for tests in one directory, ensuring that
#  the tests are serialized in file order.
#
#  This is because each of these tests runs the server, and listens on
#  either a port or a unix socket.  And (for now), all of the tests in
#  one directory use the same port.
#
define TEST_ALL_DEPS_INNER
ifeq "$(OUTPUT.${1}._serial)" ""
OUTPUT.${1}._serial := $2
else
$2: $(OUTPUT.${1}._serial)
OUTPUT.${1}._serial := $2
endif
endef

#
#  Walk through the tests with run radiusd, ensuring that the tests
#  are serialized in directory order.
#
define TEST_ALL_DEPS
$(FILES.test.${1}): $(FILES.test.radiusd-c)

$(foreach x,$(FILES.test.${1}),$(eval $(call TEST_ALL_DEPS_INNER,${1},$x)))
endef

$(foreach x,$(TEST_ALL_ORDER),$(eval $(call TEST_ALL_DEPS,$x)))
