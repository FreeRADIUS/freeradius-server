#
#  Test the "redis" module
#

#  MODULE.test is the main target for this module.

# Don't test redis if REDIS_TEST_SERVER ENV is not set
redis_require_test_server := 1

redis.test:
	${Q}echo OK: redis.test
