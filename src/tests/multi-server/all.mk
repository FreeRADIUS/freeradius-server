#
# all.mk for multi-server tests
#
# Test targets map testcase variants to a common environment compose file.
#
# For example, the test target "test-5hs-autoaccept", "test-5hs-autoaccept-5min" or
# "test-5hs-autoaccept-variant3" all map to the same compose environment.  This is
# done on purpose to allow multiple test variants to share the same base docker compose
# environment, while still having unique test YAML files.
#
#   make test-5hs-autoaccept
#     -> TEST_FILENAME     = test-5hs-autoaccept.yml
#     -> ENV_COMPOSE_PATH  = environments/docker-compose/env-5hs-autoaccept.yml
#
#   make test-5hs-autoaccept-5min
#     -> TEST_FILENAME     = test-5hs-autoaccept-5min.yml
#     -> ENV_COMPOSE_PATH  = environments/docker-compose/env-5hs-autoaccept.yml
#
#   make test-2p-2p-4hs-sql-mycustomvariantstring
#     -> TEST_FILENAME     = test-2p-2p-4hs-sql-mycustomvariantstring.yml
#     -> ENV_COMPOSE_PATH  = environments/docker-compose/env-2p-2p-4hs-sql.yml
#
# Jinja2 Template Pre-Processing:
#
# Prior to running a test, .j2 files are processed using the config_builder.py script
# of the test-framework.
#

# Find ENV compose file by stripping trailing "-suffix" chunks until a match exists.
# Returns: environments/docker-compose/env-<base-without-test->.yml
define FIND_ENV_COMPOSE
$(strip $(shell \
	name='$(1)'; base="$$name"; \
	while :; do \
		env="environments/docker-compose/env-$${base#test-}.yml"; \
		envj2="$$env.j2"; \
		if [ -f "$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$envj2" ]; then \
			printf '%s' "$$env"; exit 0; \
		elif [ -f "$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$env" ]; then \
			printf '%s' "$$env"; exit 0; \
		fi; \
		newbase="$${base%-*}"; \
		if [ "$$newbase" = "$$base" ]; then \
			echo "ERROR: No matching env compose file for $(1) (tried $$env(.j2) and shorter prefixes)" 1>&2; \
			exit 1; \
		fi; \
		base="$$newbase"; \
	done))
endef

define MAKE_TEST_TARGET
.PHONY: $(1)

$(1): TEST_NAME     := $(1)
$(1): TEST_FILENAME := $$(TEST_NAME).yml

# Compute compose path by finding the longest matching base env file
$(1): ENV_COMPOSE_PATH := $$(call FIND_ENV_COMPOSE,$$(TEST_NAME))

$(1): clone
	@echo "MULTI_SERVER_BUILD_DIR_REL_PATH=$(MULTI_SERVER_BUILD_DIR_REL_PATH)"
	@echo "MULTI_SERVER_BUILD_DIR_ABS_PATH=$(MULTI_SERVER_BUILD_DIR_ABS_PATH)"
	@mkdir -p "$(MULTI_SERVER_BUILD_DIR_REL_PATH)/freeradius-listener-logs/$$(TEST_NAME)"
	@cd "$(FRAMEWORK_REPO_DIR)" && \
		git pull && \
		\
		$(MAKE) configure && \
		. ".venv/bin/activate" && \
		\
		DATA_PATH="$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)environments/configs"; \
		LISTENER_DIR="$(MULTI_SERVER_BUILD_DIR_ABS_PATH)/freeradius-listener-logs/$$(TEST_NAME)"; \
		\
		echo "INFO: TEST_FILENAME=$$(TEST_FILENAME)"; \
		echo "INFO: TEST_NAME=$$(TEST_NAME)"; \
		echo "INFO: ENV_COMPOSE_PATH=$$(ENV_COMPOSE_PATH)"; \
		echo "INFO: MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH=$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)"; \
		echo "INFO: DATA_PATH=$$$$DATA_PATH"; \
		echo "INFO: MULTI_SERVER_BUILD_DIR_REL_PATH=$(MULTI_SERVER_BUILD_DIR_REL_PATH)"; \
		echo "INFO: LISTENER_DIR=$$$$LISTENER_DIR"; \
		\
		CMD="python3 src/config_builder.py --listener_type file --aux $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)environments/configs/freeradius/homeserver/radiusd.conf.j2 --includepath $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)"; \
		echo "INFO: CMD = $$$$CMD"; \
		bash -c "$$$$CMD"; \
		\
		CMD="python3 src/config_builder.py --listener_type file --aux $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)environments/configs/freeradius/load-generator/radiusd.conf.j2 --includepath $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)"; \
		echo "INFO: CMD = $$$$CMD"; \
		bash -c "$$$$CMD"; \
		\
		CMD="python3 src/config_builder.py --listener_type file --aux $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)environments/docker-compose/env-5hs-autoaccept.yml.j2 --includepath $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)"; \
		echo "INFO: CMD = $$$$CMD"; \
		bash -c "$$$$CMD"; \
		\
		test -f "$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$(ENV_COMPOSE_PATH)" || { \
			echo "ERROR: Missing compose file: $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$(ENV_COMPOSE_PATH)"; \
			exit 1; \
		} && \
		CMD="DATA_PATH=$(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)environments/configs make test-framework -- -x -v --compose $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$(ENV_COMPOSE_PATH) --test $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)$$(TEST_FILENAME) --use-files --listener-dir $$$$LISTENER_DIR"; \
		echo "INFO: CMD = $$$$CMD"; \
		bash -c "$$$$CMD"
endef

# Set directory name where all.mk is located. Help with relative paths
MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Set BUILD_DIR to 'build' if not already set. BUILD_DIR
# typically set by the top-level Makefile, however, we would also
# like to be able to run the targets from this file without the use of the top-level Makefile.
ifeq ($(origin BUILD_DIR), undefined)
BUILD_DIR := build
endif
FREERADIUS_SERVER_BUILD_DIR_REL_PATH := $(BUILD_DIR)

# Where we keep build-side artifacts for test-framework
MULTI_SERVER_BUILD_DIR_REL_PATH := $(FREERADIUS_SERVER_BUILD_DIR_REL_PATH)/tests/multi-server
MULTI_SERVER_BUILD_DIR_ABS_PATH := $(abspath $(MULTI_SERVER_BUILD_DIR_REL_PATH))
VENV_DIR := $(MULTI_SERVER_BUILD_DIR_REL_PATH)/.venv

FRAMEWORK_GIT_URL  ?= https://github.com/InkbridgeNetworks/freeradius-multi-server.git
FRAMEWORK_REPO_DIR ?= $(MULTI_SERVER_BUILD_DIR_REL_PATH)/freeradius-multi-server

CLONE_STAMP := $(FRAMEWORK_REPO_DIR)/.git/HEAD

.PHONY: clone
clone: $(CLONE_STAMP)

$(CLONE_STAMP): | $(MULTI_SERVER_BUILD_DIR_REL_PATH)
	@if [ -d "$(FRAMEWORK_REPO_DIR)/.git" ]; then \
		echo "Repo already cloned: $(FRAMEWORK_REPO_DIR)"; \
	else \
		git clone "$(FRAMEWORK_GIT_URL)" "$(FRAMEWORK_REPO_DIR)"; \
	fi
	@# Ensure the stamp exists even if git changes behavior
	@test -f "$@" || { echo "ERROR: clone stamp missing: $@"; exit 1; }

# Per-target variable (set by the generated targets below)
TEST_FILENAME ?=

# Discover available tests (files like test-*.yml in this directory)
TEST_YMLS  := $(notdir $(wildcard $(MULTI_SERVER_TESTS_BASE_DIR_ABS_PATH)test-*.yml))
TEST_NAMES := $(basename $(TEST_YMLS))

# Instantiate dynamic test targets for each discovered test YAML
ifndef MULTI_SERVER_TEST_TARGETS_DEFINED
MULTI_SERVER_TEST_TARGETS_DEFINED := 1
$(foreach test,$(TEST_NAMES),$(info Found test: $(test))$(eval $(call MAKE_TEST_TARGET,$(test))))
endif

all: $(TEST_NAMES)

# Ensure the target directory exists
$(MULTI_SERVER_BUILD_DIR_REL_PATH):
	@mkdir -p "$@"
