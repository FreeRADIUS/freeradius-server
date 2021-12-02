#
#  Test the "redis" module
#
cache_redis.test:

# Don't test redis if REDIS_TEST_SERVER ENV is not set
cache_redis_require_test_server := 1
