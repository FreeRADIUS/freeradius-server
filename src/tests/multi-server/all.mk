#
# all.mk for multi-server tests
#
# Makefile arguments affecting test framework debug logs and verbosity:
# - DEBUG=1 to enable debug logs from multi-server test framework
# - VERBOSE=<level> 1 for normal verbosity (default), up to 4
#

# Set required variables for Makefile
SHELL := /bin/bash

#
#  Allow for stand-alone builds from the local directory.
#
ifeq "$(BUILD_DIR)" ""
top_srcdir	:= $(abspath ./)
BUILD_DIR	:= ${top_srcdir}/build
endif

DIR := ${top_srcdir}/src/tests/multi-server
OUTPUT := $(BUILD_DIR)/tests/multi-server
MULTI_SERVER_GIT_REPO := https://github.com/InkbridgeNetworks/freeradius-multi-server.git
MULTI_SERVER_GIT_BRANCH := logging-rework

LOGDIR:= $(OUTPUT)/logs

MULTI_SERVER_LOG := $(LOGDIR)/multi-server-tests-stdout-combined.log
MULTI_SERVER_LINELOG := $(LOGDIR)/multi-server-tests-linelog-combined.log

# Enable multi-server test framework debug logs
MS_DEBUG ?= 0
MS_DEBUG_LEVEL_0 := ""
MS_DEBUG_LEVEL_1 := -x
MS_DEBUG_LEVEL_2 := -xx
MS_DEBUG_ARG := $(MS_DEBUG_LEVEL_$(MS_DEBUG))

# Multi-server test verbosity level
MS_VERBOSE ?= 1
MS_VERBOSE_LEVEL_0 := ""
MS_VERBOSE_LEVEL_1 := -v
MS_VERBOSE_LEVEL_2 := -vv
MS_VERBOSE_LEVEL_3 := -vvv
MS_VERBOSE_LEVEL_4 := -vvvv
MS_VERBOSE_ARG := $(MS_VERBOSE_LEVEL_$(MS_VERBOSE))

# Default Multi-server tests (1st target of Makefile)
# We purposely do not run all make targets here to run the short
# tests by default.
multi-server: test-5hs-autoaccept test-1p-2hs-autoaccept combine-multi-server-test-linelog

.PHONY: test.multi-server
test.multi-server: multi-server

# Clean target to remove all .log and .txt.bak files in the runtime logs directory
.PHONY: clean.test.multi-server
clean.test.multi-server:
	@echo "INFO: Removing all .log and .txt.bak files in $(LOGDIR)"
	rm -f $(LOGDIR)/*.log
	rm -f $(LOGDIR)/*.log.bak
	rm -f $(LOGDIR)/*.txt.bak

# Allow standalone use: make -f src/tests/multi-server/all.mk clean
# Prerequisite-only rule merges safely with the top-level clean target
.PHONY: clean
clean: clean.test.multi-server

# Hook into the top-level clean.test when included as a submakefile
clean.test: clean.test.multi-server

# Additional multi-server tests for longer runs
multi-server-5min: test-5hs-autoaccept-5min test-1p-2hs-autoaccept-5min combine-multi-server-test-linelog

.PHONY: env-5hs-autoaccept test-5hs-autoaccept test-5hs-autoaccept-5min env-1p-2hs-autoaccept test-1p-2hs-autoaccept test-1p-2hs-autoaccept-5min combine-multi-server-test-linelog

.phony: $(OUTPUT)
$(OUTPUT):
	@mkdir -p $@

.phony: $(LOGDIR)
$(LOGDIR):
	@mkdir -p $

env-5hs-autoaccept: | $(OUTPUT) $(LOGDIR) 
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	ENV_NAME=$@; \
	\
	echo "INFO: top_srcdir=$(top_srcdir)"; \
	echo "INFO: BUILD_DIR=$(BUILD_DIR)"; \
	echo "INFO: DIR=$(DIR)"; \
	echo "INFO: OUTPUT=$(OUTPUT)"; \
	cd $(OUTPUT); \
	\
	if [ ! -d freeradius-multi-server/.git ]; then \
		( git clone $(MULTI_SERVER_GIT_REPO) freeradius-multi-server && cd freeradius-multi-server && git checkout $(MULTI_SERVER_GIT_BRANCH)); \
	else \
		#( cd freeradius-multi-server && git pull ); \
		#( cd freeradius-multi-server ); \
		( cd freeradius-multi-server && git checkout $(MULTI_SERVER_GIT_BRANCH) && git pull ); \
	fi; \
	\
	cd freeradius-multi-server; \
	$(MAKE) configure; \
	. .venv/bin/activate; \
	\
	echo "INFO: Currently in $$(pwd)"; \
	\
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(DIR)/environments/jinja-vars/$$ENV_NAME.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(DIR)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: LOGDIR=$(LOGDIR)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	set -x; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/docker-compose/$$ENV_NAME.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \


test-5hs-autoaccept: env-5hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(OUTPUT)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(DIR)/environments/configs" \
	make test-framework \
		-- $(MS_DEBUG_ARG) $(MS_VERBOSE_ARG) \
		--compose "$(DIR)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(DIR)/$$TEST_NAME.yml" \
		--use-files \
		--listener-dir "$(LOGDIR)" \
		--log-dir "$(LOGDIR)" \
		--output "$(LOGDIR)/$$TEST_NAME-result.log"

test-5hs-autoaccept-5min: env-5hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(OUTPUT)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(DIR)/environments/configs" \
	make test-framework \
		-- $(MS_DEBUG_ARG) $(MS_VERBOSE_ARG) \
		--compose "$(DIR)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(DIR)/test-5hs-autoaccept-5min.yml" \
		--use-files \
		--listener-dir "$(LOGDIR)" \
		--log-dir "$(LOGDIR)" \
		--output "$(LOGDIR)/$$TEST_NAME-result.log"

env-1p-2hs-autoaccept:
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	ENV_NAME=$@; \
	\
	mkdir -p "$(OUTPUT)"; \
	mkdir -p "$(LOGDIR)"; \
	cd $(OUTPUT); \
	\
	if [ ! -d freeradius-multi-server/.git ]; then \
		git clone $(MULTI_SERVER_GIT_REPO); \
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
	MULTI_SERVER_ENV_VARS_FILE_PATH_ABS="$(DIR)/environments/jinja-vars/$$ENV_NAME.vars.yml"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(DIR)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: LOGDIR=$(LOGDIR)"; \
	echo "INFO: JINJA_RENDERING_SCOPE_PATH_ABS=$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	set -x; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/configs/freeradius/proxy/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \
	\
	python3 src/config_builder.py \
	--vars-file "$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS" \
	--aux-file "$(DIR)/environments/docker-compose/$$ENV_NAME.yml.j2" \
	--include-path "$$JINJA_RENDERING_SCOPE_PATH_ABS"; \


test-1p-2hs-autoaccept: env-1p-2hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(OUTPUT)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(DIR)/environments/configs" \
	make test-framework \
		-- $(MS_DEBUG_ARG) $(MS_VERBOSE_ARG) \
		--compose "$(DIR)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(DIR)/test-1p-2hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$(LOGDIR)" \
		--log-dir "$(LOGDIR)" \
		--output "$(LOGDIR)/$$TEST_NAME-result.log"

test-1p-2hs-autoaccept-5min: env-1p-2hs-autoaccept
	@LOG_FILE="$(MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$${LOG_FILE}"); \
	\
	TEST_NAME=$@; \
	\
	cd $(OUTPUT)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running $${TEST_NAME}"; \
	\
	set -x; \
	\
	DATA_PATH="$(DIR)/environments/configs" \
	make test-framework \
		-- $(MS_DEBUG_ARG) $(MS_VERBOSE_ARG) \
		--compose "$(DIR)/environments/docker-compose/env-1p-2hs-autoaccept.yml" \
		--test "$(DIR)/$$TEST_NAME.yml" \
		--use-files \
		--listener-dir "$(LOGDIR)" \
		--log-dir "$(LOGDIR)" \
		--output "$(LOGDIR)/$$TEST_NAME-result.log"

combine-multi-server-test-linelog:
	@echo "INFO: Combining multi-server test linelog message output into $(MULTI_SERVER_LINELOG)"
	@rm -f $(MULTI_SERVER_LINELOG)
	for f in $(LOGDIR)/*.txt.bak; do \
	  echo "$$f"; \
	  cat "$$f"; \
	  echo ""; \
	done > $(MULTI_SERVER_LINELOG)
