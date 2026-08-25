#
#  Test the "redis" cache module driver
#
cache_redis.test:

# Don't test redis driver if CACHE_REDIS_TEST_SERVER ENV is not set
cache_redis_require_test_server := 1

#
#  cache_redis and rediswho share a cluster of their own, so the failover
#  test in modules/redis can never kill a node under them.  The cluster's
#  base port is defined once here, and the node ports, base+1 to base+6,
#  reach the test configuration through the environment.
#
#
#  The definition is guarded, because cache_redis and rediswho both carry
#  it, and only the suites whose modules build get their makefiles included.
#
ifndef CACHE_REDIS_CLUSTER_PORT
CACHE_REDIS_CLUSTER_PORT := 30200

.PHONY: test.modules.cache_redis_bootstrap
test.modules.cache_redis_bootstrap:
	${Q}$${REDIS_CLUSTER_CONTROL:-scripts/ci/redis-setup.sh} -p $(CACHE_REDIS_CLUSTER_PORT) reset > /dev/null
endif

CACHE_REDIS_TESTS := $(patsubst src/%.unlang,$(BUILD_DIR)/%,$(wildcard src/tests/modules/cache_redis/*.unlang))

$(CACHE_REDIS_TESTS): | test.modules.cache_redis_bootstrap
$(CACHE_REDIS_TESTS): private export REDIS_CLUSTER_PORT := $(CACHE_REDIS_CLUSTER_PORT)
$(foreach n,1 2 3 4 5 6,$(eval $(CACHE_REDIS_TESTS): private export CACHE_REDIS_CLUSTER_PORT_$(n) := $(shell echo $$(($(CACHE_REDIS_CLUSTER_PORT)+$(n))))))
