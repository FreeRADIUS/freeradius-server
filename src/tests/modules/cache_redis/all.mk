#
#  Test the "redis" module
#
redis_rbtree.test:

# Don't test redis if REDIS_TEST_SERVER ENV is not set
redis_require_test_server := 1
