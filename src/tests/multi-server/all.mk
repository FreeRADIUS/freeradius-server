#
# all.mk for multi-server tests
#
# Makefile arguments affecting test framework debug logs and verbosity:
# - DEBUG=1 to enable debug logs from multi-server test framework
# - VERBOSE=<level> 1 for normal verbosity (default), up to 4
#

# Set required variables for Makefile
SHELL := /bin/bash

FREERADIUS_SERVER_SRC_PATH_REL := ./
FREERADIUS_SERVER_SRC_PATH_ABS := $(abspath $(FREERADIUS_SERVER_SRC_PATH_REL))
FREERADIUS_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/build
FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/src/tests/multi-server
FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)/tests/multi-server
FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_REPO := https://github.com/InkbridgeNetworks/freeradius-multi-server.git
FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_BRANCH := logging-rework

FREERADIUS_MULTI_SERVER_FRAMEWORK_LOG_DIR_ABS:= $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/logs
FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS := $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/logs

MULTI_SERVER_TEST_COMBINED_LOG := $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/multi-server-tests-stdout-combined.log
MULTI_SERVER_TEST_LINELOG_COMBINED_LOG := $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/multi-server-tests-linelog-combined.log

# Enable multi-server test framework debug logs
DEBUG_ARG := ""

# Multi-server test verbosity level
VERBOSE ?= 1
VERBOSE_LEVEL_0 := ""
VERBOSE_LEVEL_1 := -v
VERBOSE_LEVEL_2 := -vv
VERBOSE_LEVEL_3 := -vvv
VERBOSE_LEVEL_4 := -vvvv
VERBOSE_ARG := $(VERBOSE_LEVEL_$(VERBOSE))

# Default Multi-server tests (1st target of Makefile)
# We purposely do not run all make targets here to run the short
# tests by default.
multi-server: test-5hs-autoaccept test-1p-2hs-autoaccept combine-multi-server-test-linelog

.PHONY: test.multi-server
test.multi-server: multi-server

# Clean target to remove all .log and .txt.bak files in the runtime logs directory
.PHONY: clean.test.multi-server
clean.test.multi-server:
	@echo "INFO: Removing all .log and .txt.bak files in $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"
	rm -f $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.log
	rm -f $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.log.bak
	rm -f $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.txt.bak

# Allow standalone use: make -f src/tests/multi-server/all.mk clean
# Prerequisite-only rule merges safely with the top-level clean target
.PHONY: clean
clean: clean.test.multi-server

# Hook into the top-level clean.test when included as a submakefile
clean.test: clean.test.multi-server

# Additional multi-server tests for longer runs
multi-server-5min: test-5hs-autoaccept-5min test-1p-2hs-autoaccept-5min combine-multi-server-test-linelog

.PHONY: env-5hs-autoaccept test-5hs-autoaccept test-5hs-autoaccept-5min env-1p-2hs-autoaccept test-1p-2hs-autoaccept test-1p-2hs-autoaccept-5min combine-multi-server-test-linelog

env-5hs-autoaccept:
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	ENV_NAME=$@; \
	\
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_REL=$(FREERADIUS_SERVER_SRC_PATH_REL)"; \
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_ABS=$(FREERADIUS_SERVER_SRC_PATH_ABS)"; \
	echo "INFO: FREERADIUS_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS=$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)"; \
	\
	mkdir -p "$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)"; \
	mkdir -p "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS); \
	\
	if [ ! -d freeradius-multi-server/.git ]; then \
		( git clone $(FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_REPO) freeradius-multi-server && cd freeradius-multi-server && git checkout $(FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_BRANCH) && cd freeradius-multi-server && git checkout $(FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_BRANCH) ); \
	else \
		#( cd freeradius-multi-server && git pull ); \
		#( cd freeradius-multi-server ); \
		( cd freeradius-multi-server && git checkout $(FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_BRANCH) && git pull ); \
	fi; \
	\
	cd freeradius-multi-server; \
	$(MAKE) configure; \
	. .venv/bin/activate; \
	\
	echo "INFO: Currently in $$(pwd)"; \
	\
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/jinja-vars/$$ENV_NAME.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS=$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	set -x; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/$$ENV_NAME.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \


test-5hs-autoaccept: env-5hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/$$TEST_NAME.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--log-dir "$(FREERADIUS_MULTI_SERVER_FRAMEWORK_LOG_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TEST_NAME-result.log"

test-5hs-autoaccept-5min: env-5hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept-5min.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--log-dir "$(FREERADIUS_MULTI_SERVER_FRAMEWORK_LOG_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TEST_NAME-result.log"

env-1p-2hs-autoaccept:
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	ENV_NAME=$@; \
	\
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_REL=$(FREERADIUS_SERVER_SRC_PATH_REL)"; \
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_ABS=$(FREERADIUS_SERVER_SRC_PATH_ABS)"; \
	echo "INFO: FREERADIUS_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS=$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)"; \
	\
	mkdir -p "$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)"; \
	mkdir -p "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS); \
	\
	if [ ! -d freeradius-multi-server/.git ]; then \
		git clone $(FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_REPO); \
	else \
		#( cd freeradius-multi-server && git pull ); \
		( cd freeradius-multi-server ); \
	fi; \
	\
	cd freeradius-multi-server; \
	$(MAKE) configure; \
	. .venv/bin/activate; \
	\
	echo "INFO: Currently in $$(pwd)"; \
	\
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/jinja-vars/$$ENV_NAME.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS=$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	set -x; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs/freeradius/proxy/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/$$ENV_NAME.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \


test-1p-2hs-autoaccept: env-1p-2hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-1p-2hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--log-dir "$(FREERADIUS_MULTI_SERVER_FRAMEWORK_LOG_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TEST_NAME-result.log"

test-1p-2hs-autoaccept-5min: env-1p-2hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_TEST_COMBINED_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/$$TEST_NAME.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--log-dir "$(FREERADIUS_MULTI_SERVER_FRAMEWORK_LOG_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TEST_NAME-result.log"

combine-multi-server-test-linelog:
	@echo "INFO: Combining multi-server test linelog message output into $(MULTI_SERVER_TEST_LINELOG_COMBINED_LOG)"
	@rm -f $(MULTI_SERVER_TEST_LINELOG_COMBINED_LOG)
	for f in $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.txt.bak; do \
	  echo "$$f"; \
	  cat "$$f"; \
	  echo ""; \
	done > $(MULTI_SERVER_TEST_LINELOG_COMBINED_LOG)
