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
#  Wire each (image, type) Dockerfile rule plus the per-type regen
#  and drift-check umbrellas. Profiling is filtered to PROFILING_IMAGES
#  because it doesn't have an rpm template.
#
$(foreach IMG,$(IMAGES),\
  $(eval $(call DOCKERFILE_RULE,$(IMG),service,$(CB_DIR)/m4/service.deb.m4 $(CB_DIR)/m4/service.rpm.m4)) \
  $(eval $(call DOCKERFILE_RULE,$(IMG),ci,$(CB_DIR)/m4/ci.deb.m4 $(CB_DIR)/m4/ci.rpm.m4)) \
  $(eval $(call DOCKERFILE_RULE,$(IMG),crossbuild,$(CB_DIR)/m4/crossbuild.deb.m4 $(CB_DIR)/m4/crossbuild.rpm.m4)) \
  $(eval $(call DOCKERFILE_RULE,$(IMG),profiling-deps,$(CB_DIR)/m4/profiling-deps.deb.m4 $(CB_DIR)/m4/profiling-deps.rpm.m4)) \
  $(eval $(call DOCKERFILE_RULE,$(IMG),profiling,$(CB_DIR)/m4/profiling.deb.m4 $(CB_DIR)/m4/profiling.rpm.m4)))

$(eval $(call DOCKERFILE_ALL,dockerfile.service,service,$(IMAGES)))
$(eval $(call DOCKERFILE_ALL,dockerfile.ci,ci,$(IMAGES)))
$(eval $(call DOCKERFILE_ALL,dockerfile.crossbuild,crossbuild,$(IMAGES)))
$(eval $(call DOCKERFILE_ALL,dockerfile.profiling-deps,profiling-deps,$(IMAGES)))
$(eval $(call DOCKERFILE_ALL,dockerfile.profiling,profiling,$(IMAGES)))

$(eval $(call DOCKERFILE_CHECK,dockerfile.service.check,service,$(IMAGES),dockerfile.service))
$(eval $(call DOCKERFILE_CHECK,dockerfile.ci.check,ci,$(IMAGES),dockerfile.ci))
$(eval $(call DOCKERFILE_CHECK,dockerfile.crossbuild.check,crossbuild,$(IMAGES),dockerfile.crossbuild))
$(eval $(call DOCKERFILE_CHECK,dockerfile.profiling-deps.check,profiling-deps,$(IMAGES),dockerfile.profiling-deps))
$(eval $(call DOCKERFILE_CHECK,dockerfile.profiling.check,profiling,$(IMAGES),dockerfile.profiling))

.PHONY: dockerfile dockerfile.check
dockerfile:       dockerfile.ci       dockerfile.crossbuild       dockerfile.profiling-deps       dockerfile.profiling       dockerfile.service
dockerfile.check: dockerfile.ci.check dockerfile.crossbuild.check dockerfile.profiling-deps.check dockerfile.profiling.check dockerfile.service.check

#
#  Glossary of type identifiers, shared by docker.help / dockerfile.help.
#
define DOCKER_HELP_TYPES
	@echo "Types:"
	@echo "    service         production runtime image"
	@echo "    ci              slim toolchain base for ci-deb.yml / ci-rpm.yml"
	@echo "    crossbuild      full toolchain for docker-crossbuild.yml"
	@echo "    profiling-deps  crossbuild + valgrind / gperftools / heaptrack / kcachegrind / debug symbols"
	@echo "    profiling       profiling-deps + FreeRADIUS compiled with callgrind-friendly CFLAGS"
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
