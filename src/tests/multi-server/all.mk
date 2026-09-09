#
# all.mk for multi-server tests
#
# Makefile arguments:
# - TEST_MULTI_SERVER_DEBUG=<0-2>   debug level for multi-server test framework
# - TEST_MULTI_SERVER_VERBOSE=<0-4> verbosity level
# - MODE=<service|profiling>        which FreeRADIUS image runs the tests.
#                                   Default `service`. `profiling` selects
#                                   freeradius4-profiling/<image>:<sha> and sets
#                                   PROFILING=yes, so start_freeradius.sh runs the
#                                   server under the profiler that TOOL selects.
#                                   The profiler writes results to
#                                   PROFILING_RESULT_PATH.
# - PROFILING_RESULT_MODE=<ci|dev>  Profiling output layout (only meaningful when
#                                   MODE=profiling). Default `ci`.
#                                     ci:  PROFILING_RESULT_ROOT/<branch>/<commit>/<run-index>/<suite>/<test>
#                                     dev: PROFILING_RESULT_ROOT/<suite>/<test>  (flat)
# - TOOL=<valgrind|gperftools>      Profiler(s) to run under MODE=profiling. Default: every
#                                   known profiler, `valgrind gperftools`, in that order.
#                                     valgrind:               only profiles with valgrind
#                                     gperftools:             only profiles with gperftools
#                                     `valgrind gperftools`:  runs each test once per tool, in that order
#
# scripts/run_test.sh is the per-test recipe. scripts/start_freeradius.sh is
# the container entry point, and exec's
# scripts/profiling/start_<tool>_profiling.sh in profiling mode.
#
# Usage:
#   make -f src/tests/multi-server/all.mk test.multi-server                                          # all suites, service image
#   make -f src/tests/multi-server/all.mk test.multi-server.ci                                       # CI subset, service image
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling                                # all suites, profiling image, every profiler in turn
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling.ci                             # CI subset, profiling image, every profiler in turn
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling.ci TOOL=gperftools             # CI subset, gperftools only
#   make -f src/tests/multi-server/all.mk test.multi-server.profiling.ci TOOL=valgrind               # CI subset, valgrind only
#   make -f src/tests/multi-server/all.mk test.multi-server.accept.short_ci                          # single test
#   make -f src/tests/multi-server/all.mk clean.test.multi-server                                    # clean logs
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
#  Known profilers. TOOL selects the profilers that a profiling run uses,
#  and defaults to all of them. A space-separated TOOL list runs the test
#  once per profiler, in the order given. Each name in PROFILING_TOOLS
#  must have a scripts/profiling/start_<tool>_profiling.sh.
#
PROFILING_TOOLS := valgrind gperftools
TOOL            ?= $(PROFILING_TOOLS)

ifneq "$(filter-out $(PROFILING_TOOLS),$(TOOL))" ""
$(error TOOL must be one of: $(PROFILING_TOOLS) (got "$(TOOL)"))
endif

#
#  One radenv invocation per entry, sequentially, per test target. Service
#  mode is a single run; profiling mode is one run per profiler named in
#  TOOL.  Also verify that TOOL has not been set to be an empty string.
#
ifeq "$(MODE)" "profiling"
  ifeq "$(strip $(TOOL))" ""
    $(error MODE=profiling needs TOOL set to one or more of the following options: $(PROFILING_TOOLS))
  endif
  TEST_MULTI_SERVER_RUNS := $(TOOL)
else
  TEST_MULTI_SERVER_RUNS := service
endif

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
#  Scripts that the freeradius container runs. start_freeradius.sh is the
#  entry point that the test templates exec. start_freeradius.sh exec's
#  start_<tool>_profiling.sh when PROFILING=yes. make copies every script
#  into each test's output dir in every mode, because the compose files
#  (environments/*.yml.j2) bind mount every script, and compose turns a
#  missing bind source into an empty directory instead of an error. A tool in
#  PROFILING_TOOLS without a script fails the build early with
#  "No rule to make target .../start_<tool>_profiling.sh".
#
TEST_MULTI_SERVER_SCRIPT_DIR   := $(DIR)/scripts
TEST_MULTI_SERVER_SCRIPT_NAMES := start_freeradius.sh $(foreach t,$(PROFILING_TOOLS),start_$(t)_profiling.sh)

#
#  TEST_MULTI_SERVER_INSTANCE - define render + run targets for a single test.
#
#  The macro discovers all .j2 files in the suite directory, generates a
#  render rule for each, and creates a test target that depends on all
#  rendered outputs and on the container scripts. The test target runs
#  scripts/run_test.sh, which selects the image and the profiling settings
#  from MODE.
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

TEST_MULTI_SERVER_SCRIPTS.${1}.${2}      := $$(addprefix ${4}/scripts/,$$(TEST_MULTI_SERVER_SCRIPT_NAMES))

${4}/scripts/start_freeradius.sh: $$(TEST_MULTI_SERVER_SCRIPT_DIR)/start_freeradius.sh
	$${Q}mkdir -p $$(@D)
	$${Q}cp $$< $$@

${4}/scripts/start_%_profiling.sh: $$(TEST_MULTI_SERVER_SCRIPT_DIR)/profiling/start_%_profiling.sh
	$${Q}mkdir -p $$(@D)
	$${Q}cp $$< $$@

.PHONY: render.test.multi-server.${1}.${2}
render.test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2}) $$(TEST_MULTI_SERVER_SCRIPTS.${1}.${2})

#
#  scripts/run_test.sh is the recipe. make only resolves the make-side
#  settings into the environment of the script. Every run in
#  TEST_MULTI_SERVER_RUNS writes into the same PROFILING_RESULT_PATH, and
#  writes logs and listener files into a per-run subdirectory.
#
.PHONY: test.multi-server.${1}.${2}
test.multi-server.${1}.${2}: $$(TEST_MULTI_SERVER_RENDERED.${1}.${2}) $$(TEST_MULTI_SERVER_SCRIPTS.${1}.${2})
	${Q}MODE="$(MODE)" \
	RUNS="$(TEST_MULTI_SERVER_RUNS)" \
	FREERADIUS_SERVICE_IMAGE="$(FREERADIUS_SERVICE_IMAGE)" \
	FREERADIUS_PROFILING_IMAGE="$(FREERADIUS_PROFILING_IMAGE)" \
	PROFILING_RESULT_ROOT="$(PROFILING_RESULT_ROOT)" \
	PROFILING_RESULT_MODE="$(PROFILING_RESULT_MODE)" \
	GIT_BRANCH="$(GIT_BRANCH)" \
	GIT_COMMIT="$(GIT_COMMIT)" \
	TOP_SRCDIR="$(top_srcdir)" \
	RADENV="$(TEST_MULTI_SERVER_FRAMEWORK_DIR)/.venv/bin/radenv" \
	RADENV_FLAGS="$(TEST_MULTI_SERVER_FLAGS)" \
	$(DIR)/scripts/run_test.sh "${1}" "${2}" "${4}"
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
