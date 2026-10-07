TEST	:= test.bin

FILES	:= \
	atomic_queue_test 	\
	atomic_ring_test 	\
	control_test		\
	message_set_test	\
	radclient		\
	radict 			\
	radict_pool		\
	radict_pool_check	\
	radmin			\
	radsniff 		\
	radsnmp 		\
	rbmonkey 		\
	ring_buffer_test 	\
	rlm_redis_ippool_tool 	\
	unit_test_attribute 	\
	unit_test_map 		\
	unit_test_module

#	dhcpclient		\
#	radmin			\
#	radsniff 		\
#	radsnmp 		\
#	smbencrypt 		\
#	unit_test_attribute 	\
#	unit_test_map 		\
#	unit_test_module

#
#  Add in all of the binary tests
#
FILES += $(filter %_tests,$(ALL_TGTS))

$(eval $(call TEST_BOOTSTRAP))

#
#  Some tests take arguments, others do not.
#
control_test.ARGS = -m 1000 -w 32
radclient.ARGS = -h
radict.ARGS = -D $(top_srcdir)/share/dictionary User-Name
radmin.ARGS = -h
radsniff.ARGS =  -D $(top_srcdir)/share/dictionary -h
radsnmp.ARGS = -h
rlm_redis_ippool_tool.ARGS = -h
unit_test_attribute.ARGS = -h
unit_test_map.ARGS = -h
unit_test_module.ARGS = -h

#
#  acutest runs TEST_INIT only in the forked per-test children, so the
#  parent process, the one jlibtool's timeout signals, has no fault
#  handlers and dies with no backtrace when a test hangs.  --no-exec runs
#  every test in the one process that holds the handlers, so a hang
#  produces a backtrace naming the hung test.  The cost is isolation: a
#  crashing test takes the remaining tests in its binary with it.
#
$(foreach x,$(filter %_tests,$(ALL_TGTS)),$(eval $x.ARGS := --no-exec))

#
#  radict -P rewrites the PROTOCOL line of each protocol dictionary that
#  radict loads, so the test runs radict on a copy of the test dictionary,
#  then compares the copy with test-pool.expected.  radict loads the
#  internal dictionary from <dictdir>/freeradius, so the test copies
#  share/dictionary/freeradius beside the test dictionary.  The test
#  dictionary overflows the pool=1KB on the PROTOCOL line, so the test
#  checks the radict debug output for a reload with a larger pool.
#
RADICT_POOL_DIR := $(BUILD_DIR)/tests/bin/radict_pool.d

radict_pool.BIN = radict
radict_pool.DEPS = $(top_srcdir)/src/tests/bin/radict_pool/test-pool/dictionary \
		   $(top_srcdir)/src/tests/bin/radict_pool/test-pool.expected
radict_pool.PRE = rm -rf $(RADICT_POOL_DIR) && mkdir -p $(RADICT_POOL_DIR) && \
		  cp -R $(top_srcdir)/share/dictionary/freeradius $(top_srcdir)/src/tests/bin/radict_pool/test-pool $(RADICT_POOL_DIR)/
radict_pool.ARGS = -xx -D $(RADICT_POOL_DIR) -p test-pool -P 10
radict_pool.POST = grep -q 'Reloading the dictionaries with pools of at least' $(BUILD_DIR)/tests/bin/radict_pool.log || \
		   { echo "radict -P did not reload the test-pool dictionary after the dictionary overflowed pool=1KB"; exit 1; }; \
		   diff $(top_srcdir)/src/tests/bin/radict_pool/test-pool.expected $(RADICT_POOL_DIR)/test-pool/dictionary

#
#  Every protocol dictionary in share/dictionary must fit in the pool that
#  pool= on its PROTOCOL line sets.  A dictionary that overflows its pool
#  falls back to malloc() for every further allocation, which slows down
#  loading.  radict -O fails when any pool overflows, and names the
#  PROTOCOL line to fix with radict -P.
#
radict_pool_check.BIN = radict
radict_pool_check.DEPS = $(shell find $(top_srcdir)/share/dictionary -type f -name 'dictionary*')
radict_pool_check.ARGS = -D $(top_srcdir)/share/dictionary -O

#
#  Each test runs the binary <test>.BIN, or the binary with the same name
#  as the test, with <test>.ARGS.  <test>.DEPS adds prerequisites, and
#  <test>.PRE and <test>.POST add commands to run before and after the
#  binary.  The variables are expanded when the rules are generated, so
#  they must be set above this point.
#
define BIN_TEST
$(BUILD_DIR)/tests/bin/${1}: $(BUILD_DIR)/bin/local/$(or $(${1}.BIN),${1}) $(${1}.DEPS)
	@echo "BIN-TEST ${1}"
	$(if $(${1}.PRE),$${Q}$(${1}.PRE))
	$${Q}if ! $$(TEST_BIN)/$(or $(${1}.BIN),${1}) $(${1}.ARGS) > $$@.log 2>&1; then \
		echo LOG in $$@.log; \
		cat $$@.log; \
		echo $$(TEST_BIN)/$(or $(${1}.BIN),${1}) $(${1}.ARGS); \
		exit 1; \
	fi
	$(if $(${1}.POST),$${Q}$(${1}.POST))
	$${Q}touch $$@
endef
$(foreach x,$(FILES),$(eval $(call BIN_TEST,$x)))

#
#  Ensure that the protocol tests are run if any of the protocol dictionaries change
#
define UNIT_TEST_BIN
test.bin.$(subst _tests,,${1}): $(addprefix $(BUILD_DIR)/tests/bin/,${1})

test.bin.help: TEST_BIN_HELP += test.bin.$(subst _tests,,${1})
endef
$(foreach x,$(FILES),$(eval $(call UNIT_TEST_BIN,$x)))

test.bin.help:
	@echo make $(TEST_BIN_HELP)
