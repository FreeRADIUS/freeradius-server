#
#  Test the "mschap" module and "winbind" functionality.
#

# Don't test mschap if MSCHAP_WINBIND_TEST_SERVER ENV is not set - this indicates winbind is available
mschap_winbind_require_test_server := 1
$(eval $(call TEST_PARALLEL))
