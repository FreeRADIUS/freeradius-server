#
#  Shared macros for the m4-generated Dockerfile pipeline. Consumed
#  by scripts/docker/docker.mk (service + ci) and scripts/docker/crossbuild.mk
#  (crossbuild). DOCKER_BUILD tags every locally-built image with the
#  short commit hash and a ci-ttl label so the periodic prune workflow
#  can reap them.
#

ifndef DOCKER_MACROS_MK_INCLUDED
DOCKER_MACROS_MK_INCLUDED := 1

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
#  Image tag namespace. Every locally-built image lives under
#  $(DOCKER_IMAGE_PREFIX)-<type>/<image>:<sha>. Override per invocation
#  if a downstream needs a different namespace.
#
DOCKER_IMAGE_PREFIX ?= freeradius4

#
#  Per-build state directory. Stamps and build logs live under the
#  build/ tree so everything generator-related is in one place; the
#  hidden name keeps `ls scripts/docker/build/` tidy.
#
DOCKER_STATE := $(DT)/.state

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
#  Umbrella regen target: depends on every per-image file target.
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
#  Drift detector: re-renders each m4 template and diffs against the
#  committed Dockerfile. Non-zero exit if any file is out of sync.
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
#  Per-image build rule. Tags $(DOCKER_IMAGE_PREFIX)-<type>/<image>:<sha>,
#  labels ci-ttl=$(CI_TTL), logs to $(DOCKER_STATE)/build.<image>.<type>,
#  and touches $(DOCKER_STATE)/stamp-image.<image>.<type> so a second
#  invocation is a no-op until a dep changes.
#
#  $(1) image name
#  $(2) type
#  $(3) extra docker build args (e.g. --build-arg=from=...)
#  $(4) extra stamp-file prerequisites (e.g. base image stamp)
#
define DOCKER_BUILD
$(DOCKER_STATE)/stamp-image.${1}.${2}: $(DT)/${1}/Dockerfile.${2} ${4} | $(DOCKER_STATE)
	$${Q}echo "BUILD  $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) > $(DOCKER_STATE)/build.${1}.${2}"
	$${Q}docker build $$(DOCKER_BUILD_OPTS) ${3} \
		--label ci-ttl=$(CI_TTL) \
		-f $(DT)/${1}/Dockerfile.${2} \
		-t $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) \
		. >$(DOCKER_STATE)/build.${1}.${2} 2>&1
	$${Q}touch $$@
endef

#
#  Per-image phony shorthand: docker.<type>.<image> as an alias for
#  the build stamp, and docker.<type>.<image>.status to query whether
#  the local image is built.
#
#  $(1) image name
#  $(2) type
#
define DOCKER_PHONY
.PHONY: docker.${2}.${1} docker.${2}.${1}.status
docker.${2}.${1}: $(DOCKER_STATE)/stamp-image.${1}.${2}

docker.${2}.${1}.status:
	$${Q}docker image ls --format "\t{{.Repository}}:{{.Tag}} \t{{.CreatedAt}}" $(DOCKER_IMAGE_PREFIX)-${2}/${1}
endef

#
#  Per-image clean rule. Tries to remove the docker image; only nukes
#  the stamp if the rmi succeeded, so a failed clean (image in use by
#  a running container, etc.) leaves the state coherent for retry.
#
#  $(1) image name
#  $(2) type
#
define DOCKER_CLEAN
.PHONY: docker.${2}.${1}.clean
docker.${2}.${1}.clean:
	$${Q}if docker image rm $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) >/dev/null 2>&1; then \
		rm -f $(DOCKER_STATE)/stamp-image.${1}.${2} $(DOCKER_STATE)/build.${1}.${2}; \
		echo "CLEAN $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA)"; \
	else \
		if docker image inspect $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) >/dev/null 2>&1; then \
			echo "FAIL clean $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA): image still present (in use?)"; \
			exit 1; \
		fi; \
		rm -f $(DOCKER_STATE)/stamp-image.${1}.${2} $(DOCKER_STATE)/build.${1}.${2}; \
		echo "CLEAN $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) (no image, stamp only)"; \
	fi
endef

$(DOCKER_STATE):
	@mkdir -p $@

endif
