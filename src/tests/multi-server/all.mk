#
# all.mk for multi-server tests
#
# Makefile arguments:
# - TEST_MULTI_SERVER_DEBUG=<0-2>  debug level for multi-server test framework
# - TEST_MULTI_SERVER_VERBOSE=<0-4> verbosity level
#
# Usage:
#   make -f src/tests/multi-server/all.mk test.multi-server                         # run all tests
#   make -f src/tests/multi-server/all.mk test.multi-server.5hs-autoaccept.short    # run single test
#   make -f src/tests/multi-server/all.mk clean.test.multi-server                   # clean logs
#

SHELL := /bin/bash

#
#  Allow for stand-alone builds from the local directory.
#
ifeq "$(BUILD_DIR)" ""
top_srcdir	:= $(abspath ./)
BUILD_DIR	:= ${top_srcdir}/build
endif

DIR    := ${top_srcdir}/src/tests/multi-server
OUTPUT := $(BUILD_DIR)/tests/multi-server
LOGDIR := $(OUTPUT)/logs

# FIXME: We should be using packaged versions of the multi-server test framework
# instead of cloning from git.
TEST_MULTI_SERVER_GIT_REPO   := https://github.com/InkbridgeNetworks/freeradius-multi-server.git
TEST_MULTI_SERVER_GIT_BRANCH := logging-rework
TEST_MULTI_SERVER_FRAMEWORK_DIR := $(OUTPUT)/freeradius-multi-server

TEST_MULTI_SERVER_LOG     := $(LOGDIR)/multi-server-tests-stdout-combined.log
TEST_MULTI_SERVER_LINELOG := $(LOGDIR)/multi-server-tests-linelog-combined.log

#
#  Debug and verbosity settings
#
TEST_MULTI_SERVER_DEBUG ?= 0
TEST_MULTI_SERVER_DEBUG_LEVEL_0 :=
TEST_MULTI_SERVER_DEBUG_LEVEL_1 := -x
TEST_MULTI_SERVER_DEBUG_LEVEL_2 := -xx
TEST_MULTI_SERVER_DEBUG_ARG := $(TEST_MULTI_SERVER_DEBUG_LEVEL_$(TEST_MULTI_SERVER_DEBUG))

TEST_MULTI_SERVER_VERBOSE ?= 1
TEST_MULTI_SERVER_VERBOSE_LEVEL_0 :=
TEST_MULTI_SERVER_VERBOSE_LEVEL_1 := -v
TEST_MULTI_SERVER_VERBOSE_LEVEL_2 := -vv
TEST_MULTI_SERVER_VERBOSE_LEVEL_3 := -vvv
TEST_MULTI_SERVER_VERBOSE_LEVEL_4 := -vvvv
TEST_MULTI_SERVER_VERBOSE_ARG := $(TEST_MULTI_SERVER_VERBOSE_LEVEL_$(TEST_MULTI_SERVER_VERBOSE))

#
#  Output directories
#
$(OUTPUT):
	@mkdir -p $@

$(LOGDIR):
	@mkdir -p $@

#
#  Clone and configure the multi-server test framework.
#  This is a shared prerequisite for all test targets.
#
$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.configured: | $(OUTPUT) $(LOGDIR)
	@set -e; \
	cd $(OUTPUT); \
	if [ ! -d freeradius-multi-server/.git ]; then \
		git clone $(TEST_MULTI_SERVER_GIT_REPO) freeradius-multi-server && \
		cd freeradius-multi-server && \
		git checkout $(TEST_MULTI_SERVER_GIT_BRANCH); \
	else \
		cd freeradius-multi-server && \
		git checkout $(TEST_MULTI_SERVER_GIT_BRANCH) && \
		git pull; \
	fi; \
	cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && \
	$(MAKE) configure && \
	touch .configured

######################################################################
#
#  Macros for defining multi-server test suites.
#
#  Each suite is a directory under $(DIR) containing:
#    - template.yml.j2   Test steps template
#    - *.yml             Params files (one per test)
#    - *.j2              Symlinks to compose/config templates to render
#
######################################################################

#
#  TEST_MULTI_SERVER_RENDER - render a single .j2 template into the build dir.
#
#  Re-renders only when the .j2 source or params file changes.
#
#  ${1} = suite dir name
#  ${2} = test name (basename of params file)
#  ${3} = params file path
#  ${4} = .j2 source path
#
define TEST_MULTI_SERVER_RENDER
$$(OUTPUT)/${1}/${2}/$$(notdir $$(patsubst %.j2,%,${4})): ${4} ${3} | $$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.configured
	@mkdir -p $$(@D)
	@echo "RENDER	${4} -> $$@"
	@set -e; \
	cd $$(TEST_MULTI_SERVER_FRAMEWORK_DIR); \
	. .venv/bin/activate; \
	python3 -m src.config_builder \
	    "${4}" \
	    --vars-file "${3}" \
	    --aux-file \
	    --include-path "$$(DIR)/configs" \
	    --output-path "$$@"
endef

#
#  TEST_MULTI_SERVER_INSTANCE - define render + run targets for a single test.
#
#  Discovers all .j2 files in the suite directory, generates a render rule
#  for each, and creates a test target that depends on all rendered outputs.
#
#  ${1} = suite dir name
#  ${2} = test name
#  ${3} = params file path
#
define TEST_MULTI_SERVER_INSTANCE
TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}  := $$(wildcard $$(DIR)/tests/${1}/*.j2)
TEST_MULTI_SERVER_RENDERED.${1}.${2}     := $$(patsubst $$(DIR)/tests/${1}/%.j2,$$(OUTPUT)/${1}/${2}/%,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}))

$$(foreach j,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}),$$(eval $$(call TEST_MULTI_SERVER_RENDER,${1},${2},${3},$$j)))

.PHONY: test.multi-server.${1}.${2}
test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2})
	@LOG_FILE="$$(TEST_MULTI_SERVER_LOG)"; \
	set -e; exec &> >(tee -a "$$$$LOG_FILE"); \
	echo "INFO: Running test.multi-server.${1}.${2}"; \
	cd $$(TEST_MULTI_SERVER_FRAMEWORK_DIR); \
	. .venv/bin/activate; \
	DATA_PATH="$$(OUTPUT)/${1}/${2}" \
	python3 -m src.multi_server_test \
	    $$(TEST_MULTI_SERVER_DEBUG_ARG) $$(TEST_MULTI_SERVER_VERBOSE_ARG) \
	    --compose "$$(OUTPUT)/${1}/${2}/compose.yml" \
	    --test "$$(OUTPUT)/${1}/${2}/template.yml" \
	    --use-files \
	    --listener-dir "$$(LOGDIR)" \
	    --log-dir "$$(LOGDIR)" \
	    --output "$$(LOGDIR)/test.multi-server.${1}.${2}-result.log"
endef

#
#  TEST_MULTI_SERVER - define all test instances for a suite.
#
#  Discovers *.yml param files in the suite directory and generates
#  render + test targets for each.
#
#  ${1} = suite dir name (e.g., 5hs-autoaccept)
#
define TEST_MULTI_SERVER
TEST_MULTI_SERVER_PARAM_FILES.${1} := $$(wildcard $$(DIR)/tests/${1}/*.yml)
TEST_MULTI_SERVER_TESTS.${1}       := $$(patsubst $$(DIR)/tests/${1}/%.yml,test.multi-server.${1}.%,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}))

$$(foreach p,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}),$$(eval $$(call TEST_MULTI_SERVER_INSTANCE,${1},$$(basename $$(notdir $$p)),$$p)))
endef

######################################################################
#
#  Discover suites and generate targets
#
######################################################################

#
#  A suite is any subdirectory containing a template.yml.j2 file.
#
TEST_MULTI_SERVER_SUITES := $(notdir $(patsubst %/template.yml.j2,%,$(wildcard $(DIR)/tests/*/template.yml.j2)))

$(foreach s,$(TEST_MULTI_SERVER_SUITES),$(eval $(call TEST_MULTI_SERVER,$s)))

TEST_MULTI_SERVER_ALL_TESTS := $(foreach s,$(TEST_MULTI_SERVER_SUITES),$(TEST_MULTI_SERVER_TESTS.$(s)))

######################################################################
#
#  Top-level targets
#
######################################################################

.PHONY: test.multi-server
test.multi-server: $(TEST_MULTI_SERVER_ALL_TESTS) combine-multi-server-test-linelog

.PHONY: clean.test.multi-server
clean.test.multi-server:
	@rm -f $(LOGDIR)/*.log
	@rm -f $(LOGDIR)/*.log.bak
	@rm -f $(LOGDIR)/*.txt.bak

.PHONY: clean
clean: clean.test.multi-server

clean.test: clean.test.multi-server

.PHONY: combine-multi-server-test-linelog
combine-multi-server-test-linelog:
	@echo "INFO: Combining multi-server test linelog message output into $(TEST_MULTI_SERVER_LINELOG)"
	@rm -f $(TEST_MULTI_SERVER_LINELOG)
	@for f in $(LOGDIR)/*.txt.bak; do \
	  [ -f "$$f" ] || continue; \
	  echo "$$f"; \
	  cat "$$f"; \
	  echo ""; \
	done > $(TEST_MULTI_SERVER_LINELOG)
