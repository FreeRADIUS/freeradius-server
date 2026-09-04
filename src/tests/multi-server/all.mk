#
# all.mk for multi-server tests
#
# Makefile arguments:
# - TEST_MULTI_SERVER_DEBUG=<0-2>   debug level for multi-server test framework
# - TEST_MULTI_SERVER_VERBOSE=<0-4>  verbosity level
# - MODE=<service|profiling>        which FreeRADIUS image to drive the tests
#                                   with. Default `service`. `profiling` swaps in
#                                   freeradius4-profiling/<image>:<sha>, sets PROFILING=yes
#                                   so the test template runs the server under
#                                   valgrind/callgrind, and writes results to
#                                   PROFILING_RESULT_PATH.
# - PROFILING_RESULT_MODE=<ci|dev>      Profiling output layout (only meaningful when
#                                   MODE=profiling). Default `ci`.
#                                     ci:  PROFILING_RESULT_ROOT/<suite>/<test>/<branch>/<commit>/<run-index>
#                                     dev: PROFILING_RESULT_ROOT/<suite>/<test>  (flat)
# - TOOL=<valgrind|gperftools>      Profiler to run under MODE=profiling. Unset
#                                   (the default) runs each test once per tool,
#                                   valgrind first then gperftools, into the
#                                   same PROFILING_RESULT_PATH. The recipe
#                                   exports PROFILING_TOOL=<tool> for the test
#                                   template. Every known tool's
#                                   scripts/profiling/start_<tool>_profiling.sh
#                                   is copied into the test output dir.
#
# Usage:
#   make -f src/tests/multi-server/all.mk test.multi-server                       # all suites, service image
#   make -f src/tests/multi-server/all.mk test.multi-server.ci                    # CI subset, service image
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling             # all suites, profiling image
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling.ci          # CI subset, profiling image
#   make -f src/tests/multi-server/all.mk test.multi-server.accept.short_ci       # single test
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling.ci TOOL=gperftools  # one profiler only
#   make -f src/tests/multi-server/all.mk clean.test.multi-server                 # clean logs
#

SHELL := /bin/bash

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

GIT_BRANCH         := $(or $(shell git -C $(top_srcdir) rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '_'),unknown-branch)
GIT_COMMIT         := $(or $(shell git -C $(top_srcdir) rev-parse --short HEAD 2>/dev/null),unknown-commit)
PROFILING_RESULT_ROOT  := $(abspath $(top_srcdir)/prof-results)
PROFILING_RESULT_MODE  ?= ci

MODE ?= service

#
#  Profilers. TOOL narrows the list to one; unset runs them all, in the
#  order listed. Each name must have a scripts/profiling/start_<tool>_profiling.sh
#  and a matching branch in the test template.
#
PROFILING_TOOLS_KNOWN := valgrind gperftools
TOOL                  ?=
PROFILING_TOOLS       := $(if $(TOOL),$(TOOL),$(PROFILING_TOOLS_KNOWN))

ifneq "$(filter-out $(PROFILING_TOOLS_KNOWN),$(PROFILING_TOOLS))" ""
$(error TOOL must be one of: $(PROFILING_TOOLS_KNOWN) (got "$(TOOL)"))
endif

#
#  One radenv invocation per entry, sequentially, per test target. Service
#  mode is a single run; profiling mode is one run per profiler.
#
TEST_MULTI_SERVER_RUNS := $(if $(filter profiling,$(MODE)),$(PROFILING_TOOLS),service)

#
#  Image plumbing.
#
#  Compose envs reference ${FREERADIUS_IMAGE}; the per-test recipe
#  exports the right one based on MODE. We use the SHA-tagged image
#  that the docker.<type>.<image> rule writes, so there are no
#  intermediate :latest aliases to keep in sync.
#
#  The SHA tag does not by itself prove the image holds this commit.
#  When DOCKER_REGISTRY is set, the docker.mk build rule pulls the
#  published image and retags the pull as :<sha>.  A caller that needs
#  the image built from the checkout must pass NOPULL=1 to the
#  docker.<type>.<image> build, as ci-multi-server-tests.yml does for
#  the service image.
#
FREERADIUS_SERVICE_IMAGE     := freeradius4-service/ubuntu24:$(GIT_COMMIT)
FREERADIUS_PROFILING_IMAGE   := freeradius4-profiling/ubuntu24:$(GIT_COMMIT)

#
#  Multi-server test framework is published as a PEP 503 simple index
#  at https://pypi.inkbridge.io/ (the root serves the package listing,
#  no /simple/ suffix needed). pip uses it for the named package and
#  falls back to PyPI proper for transitive deps not hosted there.
#
RADENV_PACKAGE                  := radenv
RADENV_VERSION                  := 1.0.2
RADENV_INDEX_URL                := https://pypi.inkbridge.io/
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
#  Install the multi-server test framework into a per-build virtualenv.
#  Shared prerequisite for every test target.
#
$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.configured: | $(OUTPUT)
	$(Q)set -e; \
	mkdir -p $(TEST_MULTI_SERVER_FRAMEWORK_DIR); \
	if [ ! -d $(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv ]; then \
		python3 -m venv $(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv; \
	fi; \
	$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv/bin/pip install --quiet \
		--extra-index-url $(RADENV_INDEX_URL) \
		$(RADENV_PACKAGE)==$(RADENV_VERSION); \
	touch $@

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
	$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv/bin/radenv-config \
	    "${4}" \
	    --vars-file "${3}" \
	    --aux-file \
	    --include-path "$(DIR)/configs" \
	    --output-path "$$@" \
	    --process-volumes \
	    --volume-src "$(DIR)/configs" \
	    --define project="${1}-${2}-$(MODE)" \
	    >> "$$(@D)/config_builder.log" 2>&1
endef

#
#  Profiling helper scripts, one per known tool, copied into each test's
#  output dir regardless of MODE or TOOL so the compose bind-mounts always
#  resolve to files. The scripts are only sourced when PROFILING=yes is
#  exported into the container. A known tool without a script fails the
#  build early with "No rule to make target .../start_<tool>_profiling.sh".
#
PROFILING_SCRIPT_DIR   := $(DIR)/scripts/profiling
PROFILING_SCRIPT_NAMES := $(foreach t,$(PROFILING_TOOLS_KNOWN),start_$(t)_profiling.sh)

#
#  TEST_MULTI_SERVER_INSTANCE - define render + run targets for a single test.
#
#  Discovers all .j2 files in the suite directory, generates a render rule
#  for each, and creates a test target that depends on all rendered outputs.
#  Switches image / valgrind wiring based on MODE.
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

TEST_MULTI_SERVER_SCRIPTS.${1}.${2}      := $$(addprefix ${4}/,$$(PROFILING_SCRIPT_NAMES))

$$(TEST_MULTI_SERVER_SCRIPTS.${1}.${2}): ${4}/%: $$(PROFILING_SCRIPT_DIR)/%
	$${Q}mkdir -p $$(@D)
	$${Q}cp $$< $$@

.PHONY: render.test.multi-server.${1}.${2}
render.test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2}) $$(TEST_MULTI_SERVER_SCRIPTS.${1}.${2})

#
#  Image, PROFILING flag and result path are fixed once per test target;
#  the run loop then drives radenv once per entry in TEST_MULTI_SERVER_RUNS
#  so every profiler writes into the same PROFILING_RESULT_PATH. Logs and
#  listener files sit in a per-run subdirectory. The first failing run
#  stops the loop.
#
.PHONY: test.multi-server.${1}.${2}
test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2}) $$(TEST_MULTI_SERVER_SCRIPTS.${1}.${2})
	${Q}echo "MULTI-SERVER-TEST test.multi-server.${1}.${2} (MODE=$(MODE) RUNS=$(TEST_MULTI_SERVER_RUNS))"
	${Q}if [ "$(MODE)" = "profiling" ]; then \
		FREERADIUS_IMAGE=$(FREERADIUS_PROFILING_IMAGE); \
		PROFILING=yes; \
		if [ "$(PROFILING_RESULT_MODE)" = "dev" ]; then \
			PROFILING_RESULT_PATH="$(PROFILING_RESULT_ROOT)/${1}/${2}"; \
		else \
			RUN_BASE="$(PROFILING_RESULT_ROOT)/$(GIT_BRANCH)/$(GIT_COMMIT)"; \
			EXISTING=$$$$( find "$$$$RUN_BASE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ' ); \
			RUN_INDEX=$$$$((EXISTING + 1)); \
			PROFILING_RESULT_PATH="$$$$RUN_BASE/$$$$RUN_INDEX/${1}/${2}"; \
		fi; \
		mkdir -p "$$$$PROFILING_RESULT_PATH"; \
		echo "PROFILING_RESULT_PATH: $$$$PROFILING_RESULT_PATH"; \
	else \
		FREERADIUS_IMAGE=$(FREERADIUS_SERVICE_IMAGE); \
		PROFILING=no; \
		PROFILING_RESULT_PATH=/tmp/prof-results-unused; \
	fi; \
	for RUN in $(TEST_MULTI_SERVER_RUNS); do \
	    if [ "$$$$PROFILING" = "yes" ]; then PROFILING_TOOL="$$$$RUN"; else PROFILING_TOOL=""; fi; \
	    LOG_DIR="${4}/logs/$$$$RUN"; \
	    LISTENER_DIR="${4}/listener/$$$$RUN"; \
	    mkdir -p "$$$$LOG_DIR" "$$$$LISTENER_DIR"; \
	    echo "MULTI-SERVER-TEST test.multi-server.${1}.${2} run=$$$$RUN"; \
	    DATA_PATH="${4}" \
	    TOP_SRCDIR="$(top_srcdir)" \
	    FREERADIUS_IMAGE="$$$$FREERADIUS_IMAGE" \
	    PROFILING="$$$$PROFILING" \
	    PROFILING_TOOL="$$$$PROFILING_TOOL" \
	    PROFILING_RESULT_PATH="$$$$PROFILING_RESULT_PATH" \
	    $(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv/bin/radenv $(TEST_MULTI_SERVER_FLAGS) \
	        --project-name "${1}-${2}-$(MODE)" \
	        --compose "${4}/environment.yml" \
	        --test "${4}/template.yml" \
	        --use-files \
	        --listener-dir "$$$$LISTENER_DIR" \
	        --log-dir "$$$$LOG_DIR" \
	        --output "$$$$LOG_DIR/result.log" \
	        > "$$$$LOG_DIR/stdout.log" 2> "$$$$LOG_DIR/stderr.log" || \
	    { \
	        echo "FAILED: test.multi-server.${1}.${2} (MODE=$(MODE) run=$$$$RUN)"; \
	        for f in "$$$$LOG_DIR"/* "$$$$LISTENER_DIR"/*; do \
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
	    }; \
	done
endef

#
#  TEST_MULTI_SERVER - define all test instances for a suite.
#
#  Discovers *.yml param files in the suite directory and generates
#  render + test targets for each.
#
#  ${1} = suite dir name (e.g. accept)
#
define TEST_MULTI_SERVER
TEST_MULTI_SERVER_PARAM_FILES.${1} := $$(wildcard $$(DIR)/tests/${1}/*.test.yml)
TEST_MULTI_SERVER_TESTS.${1}       := $$(foreach p,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}),test.multi-server.${1}.$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))))

$$(foreach p,$$(TEST_MULTI_SERVER_PARAM_FILES.${1}),$$(eval $$(call TEST_MULTI_SERVER_INSTANCE,${1},$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))),$$p,$(OUTPUT)/${1}/$$(subst .,_,$$(patsubst %.test.yml,%,$$(notdir $$p))))))
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
#  Profiling pass: same suites, profiling image, valgrind wrapper. Forces
#  MODE=profiling via a recursive sub-make so the per-test recipes pick up
#  the right image / env without needing the operator to set MODE manually.
#
.PHONY: test.multi-server.profiling test.multi-server.profiling.ci
test.multi-server.profiling: freeradius-prof.image
	$(Q)$(MAKE) -f $(DIR)/all.mk test.multi-server MODE=profiling

test.multi-server.profiling.ci: freeradius-prof.image
	$(Q)$(MAKE) -f $(DIR)/all.mk test.multi-server.ci MODE=profiling

#
#  Profiling image: build the standard freeradius4-profiling/<image>:<sha>
#  via the top-level docker.profiling target. Stops short of any retag;
#  the compose envs read the SHA-tagged image name directly out of
#  FREERADIUS_IMAGE.
#
.PHONY: freeradius-prof.image
freeradius-prof.image:
	${Q}if [ -n "$(FORCE_IMAGE_REBUILD)" ] || [ -z "$$(docker images -q $(FREERADIUS_PROFILING_IMAGE) 2>/dev/null)" ]; then \
		$(MAKE) -C $(top_srcdir) docker.profiling.ubuntu24; \
	else \
		echo "$(FREERADIUS_PROFILING_IMAGE) available, skipping profiling image build"; \
	fi

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
