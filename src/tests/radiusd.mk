#
#	The "RADIUSD_SERVICE" macro is charged to start/stop the radiusd instances
# from the mostly test targets. It expects the below variables.
#
#  - Already defined by scripts/boiler.mk
#
#  DIR       = src/tests/$target
#  BUILD_DIR = build/
#  BIN_PATH  = $(BUILD_DIR)/bin/local
#
#  - Defined by the target 
#
#  PORT      := Run the service
#  TEST      := test.$target
#
#  - Parameter
#
#  ${1}		config-name found in $(DIR)/config, e.g: src/tests/$target/config/${config-name}.conf
#  ${2}		output directory
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
$$(eval RADIUSD_BIN := $(JLIBTOOL) --silent --mode=execute $$(BIN_PATH)/radiusd)

#
#  Kill it.  We don't care if it failed or not.  However, we do care
#  if we can't kill it.
#
.PHONY: $(TEST).radiusd_kill
$(TEST).radiusd_kill: | ${2}
	${Q}if [ -f ${2}/radiusd.pid ]; then \
		if ! ps `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
		    rm -f ${2}/radiusd.pid; \
		    echo "FreeRADIUS terminated during test called by $(TEST).radiusd_kill"; \
		    echo "GDB output was:"; \
		    cat "${2}/gdb.log" 2> /dev/null; \
		    echo "--------------------------------------------------"; \
		    tail -n 100 "${2}/gdb.log" 2> /dev/null; \
		    echo "Last entries in server log (${2}/gdb.log):"; \
		    exit 0; \
		fi; \
		if ! kill -TERM `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
			exit 1; \
		fi; \
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
		    echo "FreeRADIUS terminated during test called by $(TEST).radiusd_kill"; \
		    echo "GDB output was:"; \
		    cat "${2}/gdb.log" 2> /dev/null; \
		    echo "--------------------------------------------------"; \
		    tail -n 100 "${2}/gdb.log" 2> /dev/null; \
		    echo "Last entries in server log (${2}/gdb.log):"; \
		    exit 1; \
		fi; \
		if ! kill -TERM `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
			exit 1; \
		fi; \
		exit 0; \
	fi

#
#	Start radiusd instance
#
${2}/radiusd.pid: ${2}
	$$(eval RADIUSD_RUN := TESTDIR=$(DIR) OUTPUT=$(OUTPUT) TEST_PORT=$(PORT) $$(RADIUSD_BIN) -Pxxx -d $(DIR)/config -n ${1} -D share/dictionary/ -l ${2}/radiusd.log)
	${Q}rm -f ${2}/radiusd.log
	${Q}if ! $$(RADIUSD_RUN); then \
		echo "FAILED STARTING RADIUSD"; \
		grep 'Error :' "${2}/radiusd.log"; \
		echo "Last entries in server log (${2}/radiusd.log):"; \
		echo "RADIUSD_RUN: $$(RADIUSD_RUN)"; \
	fi

.PHONY: $(TEST).radiusd_start
$(TEST).radiusd_start: ${2}/radiusd.pid

#
#  If this test framework needs radiusd to be started / stopped, then ensure that
#  the output files depend on the radiusd binary.
#
ifneq "$(FILES.$(TEST))" ""
$(foreach x, $(FILES.$(TEST)), $(eval $x: $(TESTBINDIR)/radiusd $(TESTBINDIR)/$(CLIENT) $(top_srcdir)/src/tests/$(subst test.,,$(TEST))/config/${1}.conf))
endif

endef
