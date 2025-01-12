#
#  Test the "memcached" cache module driver
#
cache_memcached.test:

# Don't test memcached driver if CACHE_MEMCACHED_TEST_SERVER ENV is not set
cache_memcached_require_test_server := 1
