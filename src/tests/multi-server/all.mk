#
# all.mk for multi-server tests
#
# Makefile arguments:
# - TEST_MULTI_SERVER_DEBUG=<0-2>  debug level for multi-server test framework
# - TEST_MULTI_SERVER_VERBOSE=<0-4> verbosity level
# - PROF_MODE=<ci|dev>             profiling results path mode (default: ci)
#                                    ci:  PROF_RESULTS_ROOT/<suite>/<test>/<branch>/<commit>/<run-index>
#                                    dev: PROF_RESULTS_ROOT/<suite>/<test>  (flat, overwrites each run)
#
# Usage:
#   make -f src/tests/multi-server/all.mk test.multi-server                         # run all tests
#   make -f src/tests/multi-server/all.mk test.multi-server.ci                      # run all ci tests
#   make -f src/tests/multi-server/all.mk test.multi-server.proxy-accept.short_ci   # run single test
#   make -f src/tests/multi-server/all.mk clean.test.multi-server                   # clean logs
#

SHELL := /bin/bash

BUILD_PLATFORM ?=

#
#  Allow for stand-alone builds from the local directory.
#
ifeq "$(BUILD_DIR)" ""
top_srcdir	:= $(abspath ./)
BUILD_DIR	:= ${top_srcdir}/build
endif

# abspath is needed because BUILD_DIR is relative ("build") when
# included from the top-level makefile, but paths are passed to
# external tools (config_builder.py, docker compose) which need
# absolute paths.
DIR    := $(abspath ${top_srcdir}/src/tests/multi-server)
OUTPUT := $(abspath $(BUILD_DIR)/tests/multi-server)

GIT_BRANCH        := $(or $(shell git -C $(top_srcdir) rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '_'),unknown-branch)
GIT_COMMIT        := $(or $(shell git -C $(top_srcdir) rev-parse --short HEAD 2>/dev/null),unknown-commit)
PROF_RESULTS_ROOT := $(abspath $(top_srcdir)/prof-results)
PROF_MODE         ?= ci

# FIXME: We should be using packaged versions of the multi-server test framework
# instead of cloning from git.
TEST_MULTI_SERVER_GIT_REPO   := https://github.com/InkbridgeNetworks/radenv.git
TEST_MULTI_SERVER_GIT_BRANCH := main
TEST_MULTI_SERVER_FRAMEWORK_DIR := $(abspath $(BUILD_DIR)/radenv)

#
#  Suppress command echo unless VERBOSE is set
#
ifeq "$(VERBOSE)" ""
Q := @
else
Q :=
endif

#
#  Debug and verbosity settings
#  Pass TEST_MULTI_SERVER_FLAGS to add extra arguments to the test runner
#  e.g. make test.multi-server TEST_MULTI_SERVER_FLAGS="-x -vvv"
#
TEST_MULTI_SERVER_FLAGS ?=

#
#  Output directories
#
$(OUTPUT):
	@mkdir -p $@

#
#  Clone and configure the multi-server test framework.
#  This is a shared prerequisite for all test targets.
#
$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.configured: | $(OUTPUT)
	@set -e; \
	mkdir -p $(dir $(TEST_MULTI_SERVER_FRAMEWORK_DIR)); \
	if [ ! -d $(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.git ]; then \
		git clone $(TEST_MULTI_SERVER_GIT_REPO) $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && \
		cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && \
		git checkout $(TEST_MULTI_SERVER_GIT_BRANCH); \
	else \
		cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && \
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
#  All config source files (templates and static).
#  Used as prerequisites so that changes to any config file
#  trigger re-rendering.
#
TEST_MULTI_SERVER_CONFIG_FILES := $(shell find $(DIR)/configs -type f)

#
#  TEST_MULTI_SERVER_RENDER - render a single .j2 template into the build dir.
#
#  Re-renders only when the .j2 source, params file, or any config file changes.
#
#  ${1} = suite dir name
#  ${2} = test name (basename of params file)
#  ${3} = params file path
#  ${4} = .j2 source path
#
define TEST_MULTI_SERVER_RENDER
$(OUTPUT)/${1}/${2}/$(notdir $(patsubst %.j2,%,${4})): ${4} ${3} $(TEST_MULTI_SERVER_CONFIG_FILES) | $(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.configured
	${Q}mkdir -p $$(@D)
	${Q}echo "RENDER ${4} -> $$@"
	${Q}set -e; \
	cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR); \
	. .venv/bin/activate; \
	python3 -m src.config_builder \
	    "${4}" \
	    --vars-file "${3}" \
	    --aux-file \
	    --include-path "$(DIR)/configs" \
	    --output-path "$$@" \
	    --process-volumes \
	    --volume-src "$(DIR)/configs" \
	    >> "$$(@D)/config_builder.log" 2>&1
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
#  ${4} = test output directory
#
define TEST_MULTI_SERVER_INSTANCE
TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}  := $$(wildcard $$(DIR)/tests/${1}/*.j2)
TEST_MULTI_SERVER_RENDERED.${1}.${2}     := $$(patsubst $$(DIR)/tests/${1}/%.j2,${4}/%,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}))

$$(foreach j,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}),$$(eval $$(call TEST_MULTI_SERVER_RENDER,${1},${2},${3},$$j)))

.PHONY: render.test.multi-server.${1}.${2}
render.test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2})

.PHONY: test.multi-server.${1}.${2}
test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2})
	$$(eval CMD := cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && . .venv/bin/activate && DATA_PATH="${4}" python3 -m src.multi_server_test $(TEST_MULTI_SERVER_FLAGS) --project-name "${1}-${2}" --compose "${4}/environment.yml" --test "${4}/template.yml" --use-files --listener-dir "${4}/listener" --log-dir "${4}/logs" --output "${4}/logs/result.log")
	${Q}mkdir -p "${4}/logs" "${4}/listener"
	${Q}echo "MULTI-SERVER-TEST test.multi-server.${1}.${2}"
	${Q}$$(CMD) > "${4}/logs/stdout.log" 2> "${4}/logs/stderr.log" || \
	{ \
	    echo "FAILED: test.multi-server.${1}.${2}"; \
	    echo "$$(CMD)"; \
	    for f in ${4}/logs/* ${4}/listener/*; do \
	        [ -f "$$$$f" ] || continue; \
	        echo ""; \
	        echo "=== $$$$f ==="; \
	        case "$$$$f" in \
	            */listener/*) \
	                echo "-- line-type counts --"; \
	                awk '{print $$$$1}' "$$$$f" | sort | uniq -c; \
	                echo "-- last 200 lines --"; \
	                ;; \
	        esac; \
	        tail -200 "$$$$f"; \
	    done; \
	    exit 1; \
	}
endef

#
#  TEST_MULTI_SERVER_PROF_INSTANCE - like TEST_MULTI_SERVER_INSTANCE but
#  computes PROF_RESULTS_PATH and exports it to docker compose so valgrind
#  output lands in:
#    ci mode (default): $(PROF_RESULTS_ROOT)/<suite>/<test>/<branch>/<commit>/<run-index>
#    dev mode:          $(PROF_RESULTS_ROOT)/<suite>/<test>
#
#  ${1} = suite dir name
#  ${2} = test name
#  ${3} = params file path
#  ${4} = test output directory
#
define TEST_MULTI_SERVER_PROF_INSTANCE
TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}  := $$(wildcard $$(DIR)/tests/${1}/*.j2)
TEST_MULTI_SERVER_RENDERED.${1}.${2}     := $$(patsubst $$(DIR)/tests/${1}/%.j2,${4}/%,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}))

$$(foreach j,$$(TEST_MULTI_SERVER_JINJA_FILES.${1}.${2}),$$(eval $$(call TEST_MULTI_SERVER_RENDER,${1},${2},${3},$$j)))

.PHONY: render.test.multi-server.${1}.${2}
render.test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2})

.PHONY: test.multi-server.${1}.${2}
test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2})
	${Q}mkdir -p "${4}/logs" "${4}/listener"
	${Q}echo "MULTI-SERVER-TEST test.multi-server.${1}.${2}"
	${Q}if [ "$(PROF_MODE)" = "dev" ]; then \
		PROF_RESULTS_PATH="$(PROF_RESULTS_ROOT)/${1}/${2}"; \
	else \
		PROF_BASE="$(PROF_RESULTS_ROOT)/${1}/${2}/$(GIT_BRANCH)/$(GIT_COMMIT)"; \
		EXISTING=$$$$( find "$$$$PROF_BASE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ' ); \
		RUN_INDEX=$$$$((EXISTING + 1)); \
		PROF_RESULTS_PATH="$$$$PROF_BASE/$$$$RUN_INDEX"; \
	fi; \
	mkdir -p "$$$$PROF_RESULTS_PATH" && \
	echo "PROF_RESULTS_PATH: $$$$PROF_RESULTS_PATH" && \
	cd $(TEST_MULTI_SERVER_FRAMEWORK_DIR) && . .venv/bin/activate && \
	DATA_PATH="${4}" PROF_RESULTS_PATH="$$$$PROF_RESULTS_PATH" \
	python3 -m src.multi_server_test $(TEST_MULTI_SERVER_FLAGS) --project-name "${1}-${2}" --compose "${4}/environment.yml" --test "${4}/template.yml" --use-files --listener-dir "${4}/listener" --log-dir "${4}/logs" --output "${4}/logs/result.log" \
	> "${4}/logs/stdout.log" 2> "${4}/logs/stderr.log" || \
	{ \
	    echo "FAILED: test.multi-server.${1}.${2}"; \
	    for f in ${4}/logs/* ${4}/listener/*; do \
	        [ -f "$$$$f" ] || continue; \
	        echo ""; \
	        echo "=== $$$$f ==="; \
	        case "$$$$f" in \
	            */listener/*) \
	                echo "-- line-type counts --"; \
	                awk '{print $$$$1}' "$$$$f" | sort | uniq -c; \
	                echo "-- last 200 lines --"; \
	                ;; \
	        esac; \
	        tail -200 "$$$$f"; \
	    done; \
	    exit 1; \
	}
endef

#
#  TEST_MULTI_SERVER - define all test instances for a suite.
#
#  Discovers *.yml param files in the suite directory and generates
#  render + test targets for each.
#
#  ${1} = suite dir name (e.g. proxy-accept)
#
define TEST_MULTI_SERVER
TEST_MULTI_SERVER_PARAM_FILES.${1} := $$(wildcard $$(DIR)/tests/${1}/*.test.yml)
TEST_MULTI_SERVER_TESTS.${1}       := $$(foreach p,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}),test.multi-server.${1}.$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))))

$$(foreach p,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}),$$(eval $$(call $(if $(filter prof-%,${1}),TEST_MULTI_SERVER_PROF_INSTANCE,TEST_MULTI_SERVER_INSTANCE),${1},$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))),$$p,$(OUTPUT)/${1}/$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))))))
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

TEST_MULTI_SERVER_PROF_TESTS := $(foreach s,$(filter prof-%,$(TEST_MULTI_SERVER_SUITES)),$(TEST_MULTI_SERVER_TESTS.$(s)))

######################################################################
#
#  Top-level targets
#
######################################################################

#
#  All tests
#
.PHONY: test.multi-server
test.multi-server: $(TEST_MULTI_SERVER_ALL_TESTS)

#
#  CI tests only - matches *.ci.test.yml param files
#
TEST_MULTI_SERVER_CI_TESTS := $(filter %_ci,$(TEST_MULTI_SERVER_ALL_TESTS))

.PHONY: test.multi-server.ci
test.multi-server.ci: $(TEST_MULTI_SERVER_CI_TESTS)

#
#  Profiling tests only - all prof-* suites
#
.PHONY: test.multi-server.profiling
test.multi-server.profiling: $(TEST_MULTI_SERVER_PROF_TESTS)

#
#  Profiling CI tests only - *.ci.test.yml param files in prof-* suites
#
TEST_MULTI_SERVER_PROF_CI_TESTS := $(filter %_ci,$(TEST_MULTI_SERVER_PROF_TESTS))

.PHONY: test.multi-server.profiling.ci
test.multi-server.profiling.ci: $(TEST_MULTI_SERVER_PROF_CI_TESTS)

#
#  Ensure the freeradius-prof image is present before running any of the
#  profiling tests.
#
#  Base layer:    freeradius4-profiling/ubuntu24:<git-sha>  (built by
#                 scripts/docker/docker.mk via `make docker.profiling.ubuntu24`)
#  Test layer:    freeradius-prof:latest                   (this Makefile)
#
PROF_BASE_IMAGE       := freeradius4-profiling/ubuntu24:$(shell git -C $(top_srcdir) rev-parse --short HEAD 2>/dev/null)
FREERADIUS_PROF_IMAGE := freeradius-prof:latest

.PHONY: freeradius-prof.image
freeradius-prof.image:
	${Q}if [ -n "$(FORCE_IMAGE_REBUILD)" ] || [ -z "$$(docker images -q $(PROF_BASE_IMAGE) 2>/dev/null)" ]; then \
		$(MAKE) -C $(top_srcdir) docker.profiling.ubuntu24; \
	else \
		echo "$(PROF_BASE_IMAGE) available, skipping base profiling image build"; \
	fi
	${Q}if [ -n "$(FORCE_IMAGE_REBUILD)" ] || [ -z "$$(docker images -q $(FREERADIUS_PROF_IMAGE) 2>/dev/null)" ]; then \
		BASE_IMAGE=$(PROF_BASE_IMAGE) ./src/tests/multi-server/scripts/docker/build/build_image.sh $(if $(BUILD_PLATFORM),BUILD_PLATFORM=$(BUILD_PLATFORM)); \
	else \
		echo "$(FREERADIUS_PROF_IMAGE) available, skipping multi-server profiling image build"; \
	fi

$(TEST_MULTI_SERVER_PROF_TESTS): freeradius-prof.image

#
#  Copy the valgrind profiling helper script into each prof test's output dir
#  so it is available alongside the rendered test configs.
#
PROFILING_SCRIPT_SRC := $(DIR)/scripts/profiling/start_valgrind_profiling.sh

define TEST_MULTI_SERVER_PROF_SCRIPT
$(OUTPUT)/${1}/${2}/start_valgrind_profiling.sh: $(PROFILING_SCRIPT_SRC)
	$${Q}mkdir -p $$(@D)
	$${Q}cp $$< $$@

test.multi-server.${1}.${2}: $(OUTPUT)/${1}/${2}/start_valgrind_profiling.sh
endef

$(foreach s,$(filter prof-%,$(TEST_MULTI_SERVER_SUITES)),$(foreach p,$(TEST_MULTI_SERVER_PARAM_FILES.$(s)),$(eval $(call TEST_MULTI_SERVER_PROF_SCRIPT,$(s),$(subst .,_,$(patsubst %.test.yml,%,$(notdir $(p))))))))

.PHONY: clean.test.multi-server
clean.test.multi-server:
	${Q}rm -rf $(OUTPUT)

.PHONY: distclean.test.multi-server
distclean.test.multi-server: clean.test.multi-server
	${Q}rm -rf $(TEST_MULTI_SERVER_FRAMEWORK_DIR)

.PHONY: clean
clean: clean.test.multi-server

.PHONY: distclean
distclean: distclean.test.multi-server

clean.test: clean.test.multi-server
