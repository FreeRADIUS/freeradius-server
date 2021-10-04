BUILD_PATH      := $(top_builddir)/build
TEST_PATH       := $(top_builddir)/src/tests/radsec
BIN_PATH        := $(BUILD_PATH)/bin/local
LIB_PATH        := $(BUILD_PATH)/lib/.libs/
RADDB_PATH      := $(top_builddir)/raddb

# Naming convention for ports is like follows: port-<owner>-<description>.
# Owner may be either CoA Server, Proxy Server or Home Server
port-proxy-auth 	= 12340
port-proxy-coa 		= 12341
port-home-auth 		= 12342
port-home-coa 	 	= 12343
port-coa 	        = 12344

# Port difines for request types: auth or coa
auth-port = $(port-proxy-auth)
coa-port  = $(port-home-coa)


#
#  You can watch what it's doing by:
#
#	$ VERBOSE=1 make ... args ...
#
ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif

raddb:
	${Q}echo "Setting up raddb directory"
	${Q}cp -r $(top_builddir)/raddb $(TEST_PATH)
	${Q}rm -rf $(TEST_PATH)/raddb/sites-enabled/* # we have per server config
	${Q}echo 'detail detail_test {' >> $(TEST_PATH)/raddb/mods-enabled/detail
	${Q}echo '	filename = $${radacctdir}/detail_test' >> $(TEST_PATH)/raddb/mods-enabled/detail
	${Q}echo '}' >> $(TEST_PATH)/raddb/mods-enabled/detail
	${Q}echo 'detail detail_coa {' >> $(TEST_PATH)/raddb/mods-enabled/detail
	${Q}echo '	filename = $${radacctdir}/detail_coa' >> $(TEST_PATH)/raddb/mods-enabled/detail
	${Q}echo '}' >> $(TEST_PATH)/raddb/mods-enabled/detail

	${Q}$(MAKE) -C $(TEST_PATH)/raddb/certs

dictionary:
	${Q}echo "# test dictionary not install.  Delete at any time." > $(TEST_PATH)/dictionary
	${Q}echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> $(TEST_PATH)/dictionary


define TEST_CONF
	${Q}printf "Configuring radiusd $(1) ->  "
	${Q}echo "# radiusd test configuration file.  Do not install.  Delete at any time." > $(TEST_PATH)/test-$(1).conf
	${Q}echo "libdir =" $(LIB_PATH) >> $(TEST_PATH)/test-$(1).conf
	${Q}echo "testdir =" $(TEST_PATH) >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'logdir = $${testdir}' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'maindir = ${TEST_PATH}/raddb/' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'radacctdir = $${testdir}' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'pidfile = $${testdir}/radiusd-$(1).pid' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'panic_action = "gdb -batch -x $${testdir}/panic.gdb %e %p > $${testdir}/gdb-$(1).log 2>&1; cat $${testdir}/gdb-$(1).log"' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'security {' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo '        allow_vulnerable_openssl = yes' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo '}' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'modconfdir = $${maindir}mods-config' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'certdir = $${maindir}/certs' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo 'cadir   = $${maindir}/certs' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo '$$INCLUDE $${testdir}/config-$(1)/main.conf' >> $(TEST_PATH)/test-$(1).conf
	${Q}echo '$$INCLUDE $${maindir}/radiusd.conf' >> $(TEST_PATH)/test-$(1).conf
	${Q}rm -f $(TEST_PATH)/gdb-$(1).log $(TEST_PATH)/fr-$(1).log
endef

define START_SERVER
	${Q}printf "Starting $(1) server... "
	${Q}if ! $(BIN_PATH)/radiusd -Pxxxxml $(TEST_PATH)/fr-$(1).log -d $(TEST_PATH) -n test-$(1) -D $(TEST_PATH); then \
		echo "failed"; \
		echo "Last log entries were:"; \
		tail -n 20 "$(TEST_PATH)/fr-$(1).log"; \
	else \
		echo "ok"; \
	fi
endef

define PID_SERVER
	${Q}sed 's/$${{port-proxy-auth}}/$(port-proxy-auth)/g; \
		s/$${{port-proxy-coa}}/$(port-proxy-coa)/g; \
		s/$${{port-home-auth}}/$(port-home-auth)/g; \
		s/$${{port-home-coa}}/$(port-home-coa)/g; \
		s/$${{port-coa}}/$(port-coa)/g' \
			$(TEST_PATH)/config-$(1)/main.conf > $(TEST_PATH)/config-$(1)/main.conf
	$(call TEST_CONF,$(1))
	$(call START_SERVER,$(1))
endef

radiusd.pid: raddb dictionary
	$(call PID_SERVER,coa)
	$(call PID_SERVER,home)
	$(call PID_SERVER,proxy)

define KILL_SERVER
	${Q}if [ -f $(TEST_PATH)/radiusd-$(1).pid ]; then \
		if ! ps `cat $(TEST_PATH)/radiusd-$(1).pid` >/dev/null 2>&1; then \
			rm -f $(TEST_PATH)/radiusd-$(1).pid; \
			echo "FreeRADIUS terminated during test"; \
			echo "GDB output was:"; \
			cat "$(TEST_PATH)/gdb-$(1).log"; \
			echo "Last log entries were:"; \
			tail -n 20 $(TEST_PATH)/fr-$(1).log; \
		fi; \
		if ! kill -TERM `cat $(TEST_PATH)/radiusd-$(1).pid` >/dev/null 2>&1; then \
			echo "Cannot kill $(TEST_PATH)/radiusd-$(1).pid"; \
		fi; \
	fi
	${Q}rm -f $(TEST_PATH)/radiusd-$(1).pid $(TEST_PATH)/config-$(1)/*.conf
endef

radiusd-proxy.kill:
	$(call KILL_SERVER,proxy)
radiusd-home.kill:
	$(call KILL_SERVER,home)
radiusd-coa.kill:
	$(call KILL_SERVER,coa)

radiusd.kill: radiusd-proxy.kill radiusd-home.kill radiusd-coa.kill

# E.g: basis-auth.request -> TEST_NAME=basic-auth TYPE=auth, PORT=$(auth-port)
%.request.test:
	${Q}printf "RADSEC-TEST $@... "
	${Q}if ! TEST_NAME=$(patsubst %.request.test,%,$@) \
		TYPE=$(word 2, $(subst -, ,$(patsubst %.request.test,%,$@))) \
		PORT=$($(word 2, $(subst -, ,$(patsubst %.request.test,%,$@)))-port) \
		TEST_PATH=$(TEST_PATH) $(TEST_PATH)/runtest.sh 2>&1 > /dev/null; then \
		echo "failed"; \
	else \
		echo "ok"; \
	fi

# kill the server (if it's running)
# start the server
# run the tests
# kill the server
#TEST_FILES = 2.basic-coa.request.test
TEST_FILES = $(sort $(addsuffix .test,$(notdir $(wildcard $(TEST_PATH)/*.request))))
tests.radsec: radiusd.kill radiusd.pid $(TEST_FILES)
	${Q}$(MAKE) radiusd.kill

.PHONY: clean.tests.radsec
clean.tests.radsec: radiusd.kill
	${Q}cd $(TEST_PATH) && rm -rf raddb/ detail_coa detail_test *.result *.conf dictionary *.ok *.log *.tmp


.PHONY: radiusd.kill radiusd-proxy.kill radiusd-home.kill radiusd-coa.kill dictionary raddb
