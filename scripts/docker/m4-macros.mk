#
#  Shared macros for the m4-generated Dockerfile pipeline. Consumed
#  by scripts/docker/docker.mk (service + ci) and scripts/docker/crossbuild.mk
#  (crossbuild). DOCKER_BUILD tags every locally-built image with the
#  short commit hash and a ci-ttl label so the periodic prune workflow
#  can reap them.
#

ifndef M4_MACROS_MK_INCLUDED
M4_MACROS_MK_INCLUDED := 1

#
#  Short commit hash used as the dev-local image tag. Hub-pushed
#  images use :latest in the publish workflow and aren't subject to
#  the local prune.
#
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null)

#
#  Go-style duration string controlling how long an image survives
#  on a CI host before the periodic prune workflow removes it.
#  Image-level label, so any tag pointing at the image carries it.
#
CI_TTL ?= 60m

#
#  Per-image Dockerfile target rule.
#
#  $(1) image name (e.g. debian12, ubuntu24)
#  $(2) type (service / ci / crossbuild / profiling)
#  $(3) type-specific m4 prerequisites (the .deb.m4 / .rpm.m4 files)
#
define M4_REGEN_RULE
$(DT)/${1}/Dockerfile.${2}: $(DOCKER_TMPL) ${3} $(M4_SHARED)
	$${Q}echo REGEN ${1} "->" $$@
	$${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=${2} $$< > $$@
endef

#
#  Umbrella regen target: depends on every per-image file target.
#
#  $(1) target name (e.g. docker.service.regen)
#  $(2) type
#  $(3) image list
#
define M4_REGEN_BUNDLE
.PHONY: ${1}
${1}: $(foreach IMG,${3},$(DT)/${IMG}/Dockerfile.${2})
endef

#
#  Drift detector: re-renders each m4 template and diffs against the
#  committed Dockerfile. Non-zero exit if any file is out of sync.
#
#  $(1) target name (e.g. docker.service.regen.check)
#  $(2) type
#  $(3) image list
#  $(4) regen target the operator should run to fix drift
#
define M4_REGEN_CHECK
.PHONY: ${1}
${1}:
	@failed=0; for IMG in ${3}; do \
		tmp=$$$$(mktemp); \
		m4 -I $(CB_DIR)/m4 -D D_NAME=$$$$IMG -D D_TYPE=${2} $(DOCKER_TMPL) > $$$$tmp; \
		if ! diff -u $(DT)/$$$$IMG/Dockerfile.${2} $$$$tmp; then \
			echo "OUT OF SYNC: $(DT)/$$$$IMG/Dockerfile.${2}"; failed=1; \
		fi; \
		rm $$$$tmp; \
	done; \
	[ $$$$failed -eq 0 ] || { echo; echo "Run 'make ${4}' and commit the result."; exit 1; }
endef

#
#  Per-image build rule. Tags freeradius4-<type>/<image>:<sha>,
#  labels ci-ttl=$(CI_TTL), logs to $(DD)/build.<image>.<type>, and
#  touches $(DD)/stamp-image.<image>.<type> so a second invocation
#  is a no-op until a dep changes.
#
#  $(1) image name
#  $(2) type
#  $(3) extra docker build args (e.g. --build-arg=from=...)
#  $(4) extra stamp-file prerequisites (e.g. base image stamp)
#
define DOCKER_BUILD
$(DD)/stamp-image.${1}.${2}: $(DT)/${1}/Dockerfile.${2} ${4} | $(DD)
	$${Q}echo "BUILD ${1} (freeradius4-${2}/${1}:$(GIT_SHA)) > $(DD)/build.${1}.${2}"
	$${Q}docker build $$(DOCKER_BUILD_OPTS) ${3} \
		--label ci-ttl=$(CI_TTL) \
		-f $(DT)/${1}/Dockerfile.${2} \
		-t freeradius4-${2}/${1}:$(GIT_SHA) \
		. >$(DD)/build.${1}.${2} 2>&1
	$${Q}touch $$@
endef

$(DD):
	@mkdir -p $@

endif
