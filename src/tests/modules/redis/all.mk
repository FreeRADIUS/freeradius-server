#
#  Test the "redis" module
#

# Don't test redis if REDIS_TEST_SERVER ENV is not set
redis_require_test_server := 1

#
#  The tests use distinct keys, so they run at the same time as each other
#  against this test suite's cluster.
#
$(eval $(call TEST_PARALLEL))

#
#  One flush before the tests of a make invocation, in place of a flush per
#  test.  The script rebuilds the cluster from nothing when a node is dead
#  or no cluster is running, so a run always starts against a working
#  cluster no matter how the previous run ended.
#
#
#  The cluster's base port is defined once here.  The node ports, base+1 to
#  base+6, reach the test configuration through the environment.
#
#  The base keeps the node ports and the cluster bus ports (node port plus
#  10000, a redis convention) below the default Linux ephemeral port floor
#  of 32768.  The kernel assigns any port in the ephemeral range to an
#  outgoing connection as the connection's local port.  A node fails to
#  bind a port while a connection holds the port.
#
#  Guarded, because modules/all.mk includes this file once per test file,
#  and redefining a target's recipe makes make warn.
#
ifndef REDIS_MAIN_CLUSTER_PORT
REDIS_MAIN_CLUSTER_PORT := 21000

.PHONY: test.modules.redis_bootstrap
#
#  REDIS_CLUSTER_CONTROL substitutes the operator's own cluster control
#  script, for clusters this machine does not manage.
#
test.modules.redis_bootstrap:
	${Q}$${REDIS_CLUSTER_CONTROL:-scripts/ci/redis-setup.sh} -p $(REDIS_MAIN_CLUSTER_PORT) reset > /dev/null

REDIS_MAIN_TESTS := $(patsubst src/%.unlang,$(BUILD_DIR)/%,$(wildcard src/tests/modules/redis/*.unlang))

$(REDIS_MAIN_TESTS): | test.modules.redis_bootstrap
$(REDIS_MAIN_TESTS): private export REDIS_CLUSTER_PORT := $(REDIS_MAIN_CLUSTER_PORT)
$(foreach n,1 2 3 4 5 6,$(eval $(REDIS_MAIN_TESTS): private export REDIS_CLUSTER_PORT_$(n) := $(shell echo $$(($(REDIS_MAIN_CLUSTER_PORT)+$(n))))))

#
#  The functions test loads a deliberately slow lua function and flushes one
#  node's script cache.  A redis node runs one command at a time, so both
#  stall or error any other test on the node.  The functions test therefore
#  runs alone, after the parallel tests.
#
$(BUILD_DIR)/tests/modules/redis/functions: | $(filter-out %/functions %/cluster_node_fail,$(REDIS_MAIN_TESTS))

#
#  The failover test kills a node, so every other test has to finish first.
#
$(BUILD_DIR)/tests/modules/redis/cluster_node_fail: | $(filter-out %/cluster_node_fail,$(REDIS_MAIN_TESTS))
endif
