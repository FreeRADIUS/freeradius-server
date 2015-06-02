#
#  Test the "ldap" module
#

#  MODULE.test is the main target for this module.

# Don't test ldap if TEST_SERVER ENV is not set
ldap_require_test_server := 1

ldap.test:
	@echo OK: ldap.test
