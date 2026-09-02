#
#  Test the "rediswho" module
#

# Don't test redis if REDISWHO_TEST_SERVER ENV is not set
rediswho_require_test_server := 1

#
#  Shares the cache_redis cluster.  Nothing here kills nodes, and the two
#  suites write distinct keys, so no ordering between them is needed.
#  `modules/redis/all.mk` explains why the base port stays below the
#  ephemeral port floor.
#
#
#  The definition is guarded, because cache_redis and rediswho both carry
#  it, and only the suites whose modules build get their makefiles included.
#
ifndef CACHE_REDIS_CLUSTER_PORT
CACHE_REDIS_CLUSTER_PORT := 21200

.PHONY: test.modules.cache_redis_bootstrap
test.modules.cache_redis_bootstrap:
	${Q}$${REDIS_CLUSTER_CONTROL:-scripts/ci/redis-setup.sh} -p $(CACHE_REDIS_CLUSTER_PORT) reset > /dev/null
endif

REDISWHO_TESTS := $(patsubst src/%.unlang,$(BUILD_DIR)/%,$(wildcard src/tests/modules/rediswho/*.unlang))

$(REDISWHO_TESTS): | test.modules.cache_redis_bootstrap
$(REDISWHO_TESTS): private export REDIS_CLUSTER_PORT := $(CACHE_REDIS_CLUSTER_PORT)
$(foreach n,1 2 3 4 5 6,$(eval $(REDISWHO_TESTS): private export REDISWHO_CLUSTER_PORT_$(n) := $(shell echo $$(($(CACHE_REDIS_CLUSTER_PORT)+$(n))))))
