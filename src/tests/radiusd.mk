#
#	The "RADIUSD_SERVICE" macro is charged to start/stop the radiusd instances
# from the mostly test targets. It expects the below variables.
#
#  - Already defined by scripts/boiler.mk
#
#  DIR       = src/tests/$target
#  BUILD_DIR = build/
#
#  - Defined by the target
#
#  TEST      := test.$target
#
#  - Parameter
#
#  ${1}		config-name found in $(DIR)/config, e.g: src/tests/$target/config/${config-name}.conf
#  ${2}		output directory
#
#  - Global variables defined
#
#  <test>_port  Passing TEST=test.foo results in "foo_port" being set to the port assigned to the
#               radiusd instance created for the test suite.
#
#  - Available in calling rule
#
#  RADIUSD_RUN  The server invocation
#
#  - How to use
#
#  1. $(eval $(call RADIUSD_SERVICE,myconfig,directory/path/))
#
#  2. It will defined the targets.
#
#    $(TEST).radiusd_kill and $(TEST).radiusd_start
#
#  3. The target 'radiusd_start' define the variable $(RADIUSD_RUN) with the
#  exactly command used to start the service.
#
#  4. You could use the 'RADIUSD_BIN' to set such path to the "radiusd" binary
#  that you want to against the tests.
#
#  e.g:
#
#   make RADIUSD_BIN=/path/to/my/radiusd test
#
include Make.inc

define RADIUSD_SERVICE
$$(eval RADIUSD_BIN := $(JLIBTOOL) $(if ${VERBOSE},--debug,--silent) --mode=execute $$(TEST_BIN)/radiusd)
#
#  The package test runs an already installed server with no build tree, so the
#  allocator, which is a loadable make function, is not there.  Counting
#  upwards from the standard RADIUS port is enough, because the package test is
#  the only thing running.
#
ifdef PACKAGE_TEST
$(eval PORT := $(shell echo $$(($(PORT)+20))))
else
$(eval PORT := $(unique-port $(PORT_FILE),$(TEST),20,$(PORT_FIRST)))
endif
$(eval $(subst test.,,$(TEST))_port := $(PORT))

#
#  Kill it.  We don't care if it failed or not.  However, we do care
#  if we can't kill it.
#
.PHONY: $(TEST).radiusd_kill
$(TEST).radiusd_kill: | ${2}
	${Q}if [ -f ${2}/radiusd.pid ]; then \
		if ! ps `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
		    echo "FreeRADIUS terminated during test called by $(TEST).radiusd_kill"; \
		    rm -f ${2}/radiusd.pid; \
		    echo "GDB output was:"; \
		    cat "${2}/gdb.log" 2> /dev/null; \
		    echo "--------------------------------------------------"; \
		    echo "Last entries in server log (${2}/radiusd.log):"; \
		    tail -n 100 "${2}/radiusd.log" 2> /dev/null; \
		    exit 0; \
		fi; \
		if ! kill -9 `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
			rm -f ${2}/radiusd.pid; \
			exit 1; \
		fi; \
		rm -f ${2}/radiusd.pid; \
		exit 0; \
	fi

#
#  Stop it politely.
#
.PHONY: $(TEST).radiusd_stop
$(TEST).radiusd_stop: | ${2}
	${Q}if [ -f ${2}/radiusd.pid ]; then \
		if ! ps `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
		    rm -f ${2}/radiusd.pid; \
		    echo "FreeRADIUS terminated during test called by $(TEST).radiusd_stop"; \
		    echo "GDB output was:"; \
		    cat "${2}/gdb.log" 2> /dev/null; \
		    echo "--------------------------------------------------"; \
		    echo "Last entries in server log (${2}/radiusd.log):"; \
		    tail -n 100 "${2}/radiusd.log" 2> /dev/null; \
		    exit 1; \
		fi; \
		if ! kill -TERM `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
			exit 1; \
		fi; \
		rm -f ${2}/radiusd.pid; \
		exit 0; \
	fi

#
#	Start radiusd instance
#
#  A server left behind by an earlier run still holds the port, so the kill has
#  to finish before this rule starts a new one.  Make builds the order-only
#  prerequisites of one target at the same time under "make -j", so naming the
#  kill and the start side by side on a test output does not order them.
#
${2}/radiusd.pid: ${2} | $(TEST).radiusd_kill
	$$(eval export TESTDIR	   := $(DIR))
	$$(eval export OUTPUT	   := ${2})
	$$(eval export TEST_PORT   := $(PORT))
	$$(eval export TEST	   := $(subst test.,,$(TEST)))
	$$(eval export RADIUSD_RUN := $$(RADIUSD_BIN) -Pxxx -d $(DIR)/config -e 600 -n ${1} -D $(DICT_PATH) -l ${2}/radiusd.log)

	${Q}rm -f ${2}/radiusd.log
	${Q}if test ! -z "$$(PRINT_PORT)"; then \
		echo "$(PORT)"; \
	fi
	${Q}if ! $$(RADIUSD_RUN); then \
		echo "FAILED STARTING RADIUSD"; \
		grep 'Error :' "${2}/radiusd.log"; \
		echo "Last entries in server log (${2}/radiusd.log):"; \
		tail -n 100 "${2}/radiusd.log" 2> /dev/null; \
		echo "RADIUSD_RUN: $$(RADIUSD_RUN)"; \
	fi

.PHONY: $(TEST).radiusd_start
$(TEST).radiusd_start: ${2}/radiusd.pid

#
#  If this test framework needs radiusd to be started / stopped, then ensure that
#  the output files depend on the radiusd binary.
#
ifneq "$(FILES.$(TEST))" ""
$(foreach x, $(FILES.$(TEST)), $(eval $x: $(TEST_BIN_DIR)/radiusd $(TEST_BIN_DIR)/$(CLIENT) $(top_srcdir)/src/tests/$(subst test.,,$(TEST))/config/${1}.conf))
endif

endef
