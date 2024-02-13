#
#  Test the "mschap" module
#

# Don't test mschap if MSCHAP_TEST_SERVER ENV is not set - this indicates winbind is available
mschap_require_test_server := 1
