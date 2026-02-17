#
# all.mk for multi-server tests
#

# Set required variables for Makefile
FREERADIUS_SERVER_SRC_PATH_REL := ./
FREERADIUS_SERVER_SRC_PATH_ABS := $(abspath $(FREERADIUS_SERVER_SRC_PATH_REL))
FREERADIUS_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/build
FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS := $(FREERADIUS_SERVER_SRC_PATH_ABS)/src/tests/multi-server
FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS := $(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)/tests/multi-server
FREERADIUS_MULTI_SERVER_FRAMEWORK_GIT_REPO := https://github.com/InkbridgeNetworks/freeradius-multi-server.git

.PHONY: 5hs-autoaccept-env-setup test-5hs-autoaccept test-5hs-autoaccept-5min test-5hs-autoaccept-full-config-and-run

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
	MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS="$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-listener-logs"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS=$$MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS"; \
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
	MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS="$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-listener-logs"; \
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-5hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- -x -v \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$$MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS"

test-5hs-autoaccept-5min: 5hs-autoaccept-env-setup
	@set -e; \
	\
	MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS="$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-listener-logs"; \
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-multi-server; \
	. .venv/bin/activate; \
	\
	echo "INFO: Running test-5hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- -x -v \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept-5min.yml" \
		--use-files \
		--listener-dir "$$MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS"

test-5hs-autoaccept-full-config-and-run:
	@set -e; \
	\
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_REL=$(FREERADIUS_SERVER_SRC_PATH_REL)"; \
	echo "INFO: FREERADIUS_SERVER_SRC_PATH_ABS=$(FREERADIUS_SERVER_SRC_PATH_ABS)"; \
	echo "INFO: FREERADIUS_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_SERVER_BUILD_DIR_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS=$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS=$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)"; \
	\
	cd $(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS); \
	\
	if [ ! -d freeradius-multi-server/.git ]; then \
		git clone https://github.com/InkbridgeNetworks/freeradius-multi-server.git; \
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
	MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS="$(FREERADIUS_MULTI_SERVER_BUILD_DIR_PATH_ABS)/freeradius-listener-logs"; \
	JINJA_RENDERING_SCOPE_PATH_ABS="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)"; \
	echo "INFO: MULTI_SERVER_ENV_VARS_FILE_PATH_ABS=$$MULTI_SERVER_ENV_VARS_FILE_PATH_ABS"; \
	echo "INFO: MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS=$$MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS"; \
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
	echo "INFO: Running test-5hs-autoaccept test using framework"; \
	DATA_PATH="$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/configs" \
	make test-framework \
		-- -x -v \
		--compose "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/environments/docker-compose/env-5hs-autoaccept.yml" \
		--test "$(FREERADIUS_MULTI_SERVER_TESTS_BASE_PATH_ABS)/test-5hs-autoaccept.yml" \
		--use-files \
		--listener-dir "$$MULTI_SERVER_FRAMEWORK_LISTENER_LOGS_DIR_ABS"
