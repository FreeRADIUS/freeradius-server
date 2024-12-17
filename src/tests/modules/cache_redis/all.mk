#
#  Test the "redis" cache module driver
#
cache_redis.test:

# Don't test redis driver if CACHE_REDIS_TEST_SERVER ENV is not set
cache_redis_require_test_server := 1
