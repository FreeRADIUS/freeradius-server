#
#	The "RADIUSD_SERVICE" macro is charged to start/stop the radiusd instances
# from the mostly test targets. It expects the below variables.
#
#  - Already defined by scripts/boiler.mk
#
#  DIR.      = src/tests/$target
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
#
include Make.inc

define RADIUSD_SERVICE
.PHONY: $(TEST).radiusd_kill
$(TEST).radiusd_kill: | ${2}
	@echo "Clean up ${2}/radiusd.pid"
	${Q}if [ -f ${2}/radiusd.pid ]; then \
		ret=0; \
		if ! ps `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
		    rm -f ${1}; \
		    echo "FreeRADIUS terminated during test called by $(TEST).radiusd_kill"; \
		    echo "GDB output was:"; \
		    cat "${2}/gdb.log"; \
		    echo "--------------------------------------------------"; \
		    tail -n 40 "${2}/gdb.log"; \
		    echo "Last entries in server log (${2}/gdb.log):"; \
		    ret=1; \
		fi; \
		if ! kill -TERM `cat ${2}/radiusd.pid` >/dev/null 2>&1; then \
			ret=1; \
		fi; \
		exit ${ret}; \
	fi

#
#	Start radiusd instance
#
${2}/radiusd.pid: ${2}
	${Q}rm -f ${2}/radiusd.log ${2}/radiusd.log
	${Q}echo "Starting RADIUSD test server for (target=$(TEST),config_dir=$(DIR)/config,config_name=${1})"
	${Q}if ! TEST_PORT=$(PORT) $(JLIBTOOL) --mode=execute $$(BIN_PATH)/radiusd -Pxxxl ${2}/radiusd.log -d $(DIR)/config -n ${1} -D "${top_builddir}/share/dictionary/"; then\
		echo "FAILED STARTING RADIUSD"; \
		tail -n 40 "${2}/radiusd.log"; \
		echo "Last entries in server log (${2}/radiusd.log):"; \
		echo "TEST_PORT=$(PORT) $(JLIBTOOL) --mode=execute $(BIN_PATH)/radiusd -Pxxxl ${2}/radiusd.log -d $(DIR)/config -n ${1} -D \"${top_builddir}/share/dictionary/\""; \
	else \
		echo "ok"; \
	fi

$(TEST).radiusd_start: ${2}/radiusd.pid
endef
