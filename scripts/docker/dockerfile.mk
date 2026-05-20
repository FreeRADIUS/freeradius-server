#
#  Dockerfile generation. m4 templates under scripts/docker/m4/ plus
#  the dispatcher Dockerfile.m4 render one Dockerfile.<type> per
#  (image, type) combination under scripts/docker/build/<image>/.
#  Image and container lifecycle live in docker.mk; this file is
#  pure file-generation plumbing.
#

ifndef DOCKERFILE_MK_INCLUDED
DOCKERFILE_MK_INCLUDED := 1

# Top level of scripts/docker. $(dir ...) leaves a trailing slash;
# strip it plus the leading project-root prefix so paths in the
# emitted echo and docker commands stay short.
CB_DIR := $(patsubst $(CURDIR)/%,%,$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST))))))

# Per-image build directory: one subdir per distro under build/.
DT := $(CB_DIR)/build

# Top-level m4 dispatcher.
DOCKERFILE_TMPL := $(CB_DIR)/m4/Dockerfile.m4

# Shared m4 snippets included by content templates. Editing one of
# these invalidates every generated Dockerfile.
DOCKERFILE_M4_SHARED := $(wildcard $(CB_DIR)/m4/common.*.m4) $(wildcard $(CB_DIR)/m4/_*.m4)

# Every distro under build/ is an image we generate Dockerfiles for.
IMAGES := $(sort $(patsubst $(DT)/%,%,$(wildcard $(DT)/*)))


# $(Q) silences recipe lines unless VERBOSE is set. Defined here so
# the macros below work whether dockerfile.mk is included alone or
# through docker.mk.
ifeq "${VERBOSE}" ""
    Q := @
else
    Q :=
endif

#
#  Per-image Dockerfile target rule.
#
#  $(1) image name (e.g. debian12, ubuntu24)
#  $(2) type (service / ci / crossbuild / profiling)
#  $(3) type-specific m4 prerequisites (the .deb.m4 / .rpm.m4 files)
#
define DOCKERFILE_RULE
$(DT)/${1}/Dockerfile.${2}: $(DOCKERFILE_TMPL) ${3} $(DOCKERFILE_M4_SHARED)
	$${Q}echo "REGEN  $$@"
	$${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=${2} $$< > $$@
endef

#
#  Umbrella regen target.
#
#  $(1) target name (e.g. dockerfile.service)
#  $(2) type
#  $(3) image list
#
define DOCKERFILE_ALL
.PHONY: ${1}
${1}: $(foreach IMG,${3},$(DT)/${IMG}/Dockerfile.${2})
endef

#
#  Drift detector. Re-renders each m4 template and diffs against the
#  committed Dockerfile; non-zero exit if any file is out of sync.
#
#  $(1) target name (e.g. dockerfile.service.check)
#  $(2) type
#  $(3) image list
#  $(4) regen target the operator should run to fix drift
#
define DOCKERFILE_CHECK
.PHONY: ${1}
${1}:
	@failed=0; for IMG in ${3}; do \
		tmp=$$$$(mktemp); \
		m4 -I $(CB_DIR)/m4 -D D_NAME=$$$$IMG -D D_TYPE=${2} $(DOCKERFILE_TMPL) > $$$$tmp; \
		if ! diff -u $(DT)/$$$$IMG/Dockerfile.${2} $$$$tmp; then \
			echo "OUT OF SYNC: $(DT)/$$$$IMG/Dockerfile.${2}"; failed=1; \
		fi; \
		rm $$$$tmp; \
	done; \
	[ $$$$failed -eq 0 ] || { echo; echo "Run 'make ${4}' and commit the result."; exit 1; }
endef

#
#  Build types. Per-type m4 prereqs follow the <type>.deb.m4 /
#  <type>.rpm.m4 naming convention so DOCKERFILE_RULE picks them up
#  from $(T) alone.
#
DOCKERFILE_TYPES := ci crossbuild profiling service

#
#  Wire each (image, type) Dockerfile rule plus the per-type regen
#  and drift-check umbrellas.
#
$(foreach IMG,$(IMAGES), \
  $(foreach T,$(DOCKERFILE_TYPES), \
    $(eval $(call DOCKERFILE_RULE,$(IMG),$(T),$(CB_DIR)/m4/$(T).deb.m4 $(CB_DIR)/m4/$(T).rpm.m4))))

$(foreach T,$(DOCKERFILE_TYPES), \
  $(eval $(call DOCKERFILE_ALL,dockerfile.$(T),$(T),$(IMAGES))) \
  $(eval $(call DOCKERFILE_CHECK,dockerfile.$(T).check,$(T),$(IMAGES),dockerfile.$(T))))

.PHONY: dockerfile dockerfile.check
dockerfile:       $(foreach T,$(DOCKERFILE_TYPES),dockerfile.$(T))
dockerfile.check: $(foreach T,$(DOCKERFILE_TYPES),dockerfile.$(T).check)

#
#  Glossary of type identifiers, shared by docker.help / dockerfile.help.
#
define DOCKER_HELP_TYPES
	@echo "Types:"
	@echo "    service     production runtime image"
	@echo "    ci          slim toolchain base for ci-deb.yml / ci-rpm.yml"
	@echo "    crossbuild  full toolchain for crossbuild.yml"
	@echo "    profiling   crossbuild + valgrind / gperftools / heaptrack / kcachegrind / debug symbols"
endef

.PHONY: dockerfile.help
dockerfile.help:
	@echo ""
	@echo "Dockerfile generation (m4 templates -> scripts/docker/build/IMAGE/Dockerfile.TYPE):"
	@echo "    dockerfile                        - regenerate every Dockerfile across every type"
	@echo "    dockerfile.check                  - fail if any Dockerfile is stale"
	@echo "    dockerfile.TYPE                   - regenerate every Dockerfile of one type"
	@echo "    dockerfile.TYPE.check             - fail if any Dockerfile of one type is stale"
	@echo ""
	$(DOCKER_HELP_TYPES)
	@echo ""
	@echo "Run 'make docker.help' for image / container lifecycle targets."

endif
