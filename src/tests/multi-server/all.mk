#
# all.mk for multi-server tests
#
# Makefile arguments affecting test framework debug logs and verbosity:
# - DEBUG=1 to enable debug logs from multi-server test framework
# - VERBOSE=<level> 1 for normal verbosity (default), up to 4
#

# Set required variables for Makefile
FREERADIUS_SERVER_SRC_PATH_REL := ./
FREERADIUS_SERVER_SRC_PATH_ABS := $(abspath $(FREERADIUS_SERVER_SRC_PATH_REL))
FREERADIUS_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/build
FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/src/tests/multi-server
FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)/tests/multi-server
FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_REPO := https://github.com/InkbridgeNetworks/freeradius-multi-server.git

FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS := $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server-test-runtime-logs

MULTI_SERVER_TEST_RESULTS_LOG := $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/multi-server-test-results-combined.log
MULTI_SERVER_TEST_LISTENER_LOG := $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/multi-server-test-listener-combined.log

# Enable multi-server test framework debug logs if DEBUG is set to 1
DEBUG ?= 0
DEBUG_ARG := $(if $(filter 1,$(DEBUG)),-x,)

# Multi-server test verbosity level
VERBOSE ?= 1
VERBOSE_LEVEL_1 := -v
VERBOSE_LEVEL_2 := -vv
VERBOSE_LEVEL_3 := -vvv
VERBOSE_LEVEL_4 := -vvvv
VERBOSE_ARG := $(VERBOSE_LEVEL_$(VERBOSE))

# Default Multi-server tests (1st target of Makefile)
multi-server: test-5hs-autoaccept test-1p-2hs-autoaccept combine-test-results
# Additional multi-server tests for longer runs
multi-server-5min: test-5hs-autoaccept-5min test-1p-2hs-autoaccept-5min combine-test-results

.PHONY: 5hs-autoaccept-env-setup test-5hs-autoaccept test-5hs-autoaccept-5min 1p-2hs-autoaccept-env-setup test-1p-2hs-autoaccept test-1p-2hs-autoaccept-5min combine-test-results

5hs-autoaccept-env-setup:
	@set -e; \
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
		( cd freeradius-multi-server && git pull ); \
	fi; \
	\
	cd freeradius-multi-server; \
	$(MAKE) configure; \
	. .venv/bin/activate; \
	\
	echo "INFO: Currently in $$(pwd)"; \
	\
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/jinja-vars/env-5hs-autoaccept.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS=$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
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
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\

test-5hs-autoaccept: 5hs-autoaccept-env-setup
	@set -e; \
	\
	TARGET_NAME=test-5hs-autoaccept; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-5hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TARGET_NAME.log"

test-5hs-autoaccept-5min: 5hs-autoaccept-env-setup
	@set -e; \
	\
	TARGET_NAME=test-5hs-autoaccept-5min; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-5hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept-5min.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TARGET_NAME.log"

1p-2hs-autoaccept-env-setup:
	@set -e; \
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
		( cd freeradius-multi-server && git pull ); \
	fi; \
	\
	cd freeradius-multi-server; \
	$(MAKE) configure; \
	. .venv/bin/activate; \
	\
	echo "INFO: Currently in $$(pwd)"; \
	\
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/jinja-vars/env-1p-2hs-autoaccept.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS=$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
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
	--aux-file "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-1p-2hs-autoaccept.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\

test-1p-2hs-autoaccept: 1p-2hs-autoaccept-env-setup
	@set -e; \
	\
	TARGET_NAME=test-1p-2hs-autoaccept; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-1p-2hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-1p-2hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TARGET_NAME.log"

test-1p-2hs-autoaccept-5min: 1p-2hs-autoaccept-env-setup
	@set -e; \
	\
	TARGET_NAME=test-1p-2hs-autoaccept-5min; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-1p-2hs-autoaccept-5min test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- $(DEBUG_ARG) $(VERBOSE_ARG) \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-1p-2hs-autoaccept-5min.yml" \
		--use-files \
		--listener-dir "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)" \
		--output "$(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/$$TARGET_NAME.log"

combine-test-results:
	@echo "INFO: Combining test results into $(MULTI_SERVER_TEST_RESULTS_LOG)"
	@rm -f $(MULTI_SERVER_TEST_RESULTS_LOG) $(MULTI_SERVER_TEST_LISTENER_LOG)
	cat $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.log > $(MULTI_SERVER_TEST_RESULTS_LOG)
	cat $(FREERADIUS_MULTI_SERVER_TEST_RUNTIME_LOGS_DIR_ABS)/*.txt.bak > $(MULTI_SERVER_TEST_LISTENER_LOG)
