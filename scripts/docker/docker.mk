#
#  Docker image + container lifecycle. Pulls Dockerfile generation
#  in via dockerfile.mk; this file owns building images from those
#  Dockerfiles plus per-image container up / down / sh / log / reset
#  and an in-container test cycle. Type-agnostic: targets for every
#  declared TYPE come from one set of macros. Legacy crossbuild.*
#  command aliases live in crossbuild.mk.
#

ifeq ($(shell which docker 2> /dev/null),)
.PHONY: docker docker.help
docker docker.help:
	@echo docker targets require Docker to be installed
else

#
#  Short list of common-case images: `make docker` without further
#  qualification falls back to this set.
#
DOCKER_COMMON := ubuntu22

# dockerfile.mk owns CB_DIR / DT / IMAGES / PROFILING_IMAGES / Q.
include scripts/docker/dockerfile.mk

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
#  $(DOCKER_IMAGE_PREFIX)-<type>/<image>:<sha>. Override per
#  invocation if a downstream needs a different namespace.
#
DOCKER_IMAGE_PREFIX ?= freeradius4

#
#  Per-build state directory. Stamps and build/test logs land in the
#  top-level build/ tree alongside every other generated artifact;
#  the dir is created on demand and the whole build/ is gitignored.
#
DOCKER_STATE := build/docker

# Absolute path to the .git dir (may differ for submodules). Bind-
# mounted read-only into lifecycle containers so they see the source.
GITDIR := $(shell perl -MCwd -e 'print Cwd::abs_path shift' $$(git rev-parse --git-dir))

# Pass NOCACHE=1 on the make line to disable docker's build cache.
ifneq "$(NOCACHE)" ""
    DOCKER_BUILD_OPTS += --no-cache
endif

#
#  Optional registry to try as a pull-through cache before rebuilding
#  any docker.<type>.<image> from scratch. Set DOCKER_REGISTRY in the
#  environment (or make.conf / a -e flag) to e.g.
#  docker.internal.networkradius.com and every build rule will first
#  attempt `docker pull <REGISTRY>/<prefix>-<type>/<image>:<sha>` with
#  a short timeout, retag locally on success, and skip the build.
#  Falls through to the local build if the pull fails for any reason
#  (no registry configured, pull times out, image not in registry,
#  auth missing). DOCKER_PULL_TIMEOUT bounds the per-pull wait so a
#  hung registry doesn't stall a dev rebuild forever; bypass the
#  registry path entirely with NOPULL=1.
#
DOCKER_REGISTRY     ?=
DOCKER_PULL_TIMEOUT ?= 30

#
#  Per-image build rule. Tags $(DOCKER_IMAGE_PREFIX)-<type>/<image>:<sha>,
#  labels ci-ttl=$(CI_TTL), logs to $(DOCKER_STATE)/build.<image>.<type>,
#  and touches $(DOCKER_STATE)/stamp-image.<image>.<type> so a second
#  invocation is a no-op until a dep changes.
#
#  When DOCKER_REGISTRY is set the rule first tries to pull the
#  matching SHA-tagged image from the registry (capped at
#  DOCKER_PULL_TIMEOUT seconds). Hit > retag locally + touch stamp,
#  no build runs. Miss > fall through to the normal docker build.
#
#  $(1) image name
#  $(2) type
#  $(3) extra docker build args (e.g. --build-arg=from=...)
#  $(4) extra stamp-file prerequisites (e.g. base image stamp)
#
define DOCKER_BUILD
$(DOCKER_STATE)/stamp-image.${1}.${2}: $(DT)/${1}/Dockerfile.${2} ${4} | $(DOCKER_STATE)
	$${Q}set -e; \
	if [ -z "$(NOPULL)" ] && [ -n "$(DOCKER_REGISTRY)" ] && \
	   timeout $(DOCKER_PULL_TIMEOUT) docker pull -q \
	           "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest" \
	           >$(DOCKER_STATE)/pull.${1}.${2} 2>&1; then \
		docker tag "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest" \
		           "$(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest"; \
		docker tag "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest" \
		           "$(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA)"; \
		echo "PULL   $(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest < $(DOCKER_REGISTRY)"; \
	else \
		echo "BUILD  $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) > $(DOCKER_STATE)/build.${1}.${2}"; \
		docker build $$(DOCKER_BUILD_OPTS) ${3} \
			--label ci-ttl=$(CI_TTL) \
			-f $(DT)/${1}/Dockerfile.${2} \
			-t $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) \
			-t $(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest \
			. >$(DOCKER_STATE)/build.${1}.${2} 2>&1; \
	fi
	$${Q}touch $$@
endef

#
#  Per-image phony shorthand. docker.<type>.<image> as a build alias,
#  docker.<type>.<image>.status to query whether the local image is
#  built, docker.<type>.<image>.tag to point the current SHA tag at
#  the already-built :latest image (no rebuild). No-op if the SHA tag
#  exists; fails loudly if no :latest image is built yet.
#
define DOCKER_PHONY
.PHONY: docker.${2}.${1} docker.${2}.${1}.status docker.${2}.${1}.tag
docker.${2}.${1}: $(DOCKER_STATE)/stamp-image.${1}.${2}

docker.${2}.${1}.status:
	$${Q}docker image ls --format "\t{{.Repository}}:{{.Tag}} \t{{.CreatedAt}}" $(DOCKER_IMAGE_PREFIX)-${2}/${1}

docker.${2}.${1}.tag:
	$${Q}if docker image inspect $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) >/dev/null 2>&1; then \
		echo "TAG   $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) already present"; \
	elif docker image inspect $(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest >/dev/null 2>&1; then \
		docker tag $(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest $(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA); \
		echo "TAG   $(DOCKER_IMAGE_PREFIX)-${2}/${1}:latest > :$(GIT_SHA)"; \
	else \
		echo "FAIL tag $(DOCKER_IMAGE_PREFIX)-${2}/${1}: no :latest image (try 'make docker.${2}.${1}')"; \
		exit 1; \
	fi
endef

#
#  Per-image full-clean rule. Tries to remove the docker image; only
#  nukes the stamp + log if the rmi succeeded, so a failed clean
#  (image still in use by a running container) leaves the state
#  coherent for retry.
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

#
#  Per-image container lifecycle. The container sleeps forever with
#  /srv/src bind-mounted to the host git tree (read-only) so an
#  operator can drop into any image and run the project's tooling
#  against the working source.
#
#  Container name pattern: $(DOCKER_IMAGE_PREFIX)-<type>-<image>.
#
define DOCKER_LIFECYCLE
.PHONY: docker.${2}.${1}.up docker.${2}.${1}.down docker.${2}.${1}.sh \
        docker.${2}.${1}.log docker.${2}.${1}.reset

docker.${2}.${1}.up: $(DOCKER_STATE)/stamp-image.${1}.${2} | $(DOCKER_STATE)
	$${Q}docker container inspect $(DOCKER_IMAGE_PREFIX)-${2}-${1} >/dev/null 2>&1 || { \
		echo "START $(DOCKER_IMAGE_PREFIX)-${2}-${1}"; \
		docker run -d --rm \
			--privileged --cap-add=ALL \
			--mount=type=bind,source="$(GITDIR)",destination=/srv/src,ro \
			--name $(DOCKER_IMAGE_PREFIX)-${2}-${1} \
			$(DOCKER_IMAGE_PREFIX)-${2}/${1}:$(GIT_SHA) \
			/bin/sh -c 'while true; do sleep 60; done' >/dev/null; \
		touch $(DOCKER_STATE)/stamp-up.${1}.${2}; \
	}

docker.${2}.${1}.down:
	$${Q}docker container kill $(DOCKER_IMAGE_PREFIX)-${2}-${1} >/dev/null 2>&1 || true
	$${Q}rm -f $(DOCKER_STATE)/stamp-up.${1}.${2}
	$${Q}echo "STOP  $(DOCKER_IMAGE_PREFIX)-${2}-${1}"

docker.${2}.${1}.sh: docker.${2}.${1}.up
	$${Q}docker exec -it $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -c 'cd /; cd /srv/build 2>/dev/null; bash' || true

docker.${2}.${1}.log:
	@if   [ ! -e $(DOCKER_STATE)/build.${1}.${2} ]; then \
	         echo "no build log for $(DOCKER_IMAGE_PREFIX)-${2}/${1} (try 'make docker.${2}.${1}' first)"; \
	elif which less >/dev/null 2>&1; then less +G $(DOCKER_STATE)/build.${1}.${2}; \
	elif which more >/dev/null 2>&1; then more  $(DOCKER_STATE)/build.${1}.${2}; \
	else cat $(DOCKER_STATE)/build.${1}.${2}; fi

docker.${2}.${1}.reset:
	$${Q}rm -f $(DOCKER_STATE)/stamp-image.${1}.${2} $(DOCKER_STATE)/stamp-up.${1}.${2} $(DOCKER_STATE)/build.${1}.${2}
	$${Q}echo "RESET $(DOCKER_IMAGE_PREFIX)-${2}/${1}"
endef

#
#  Per-image test cycle: refresh the source into a writable build tree
#  inside the running container, then run configure + make + make test.
#  Generic across types -- applied selectively by callers (e.g. the
#  crossbuild test workflow only wants this for the crossbuild type).
#
define DOCKER_TEST
.PHONY: docker.${2}.${1}.refresh docker.${2}.${1}.test

docker.${2}.${1}.refresh: docker.${2}.${1}.up
	$${Q}echo "REFRESH $(DOCKER_IMAGE_PREFIX)-${2}-${1}"
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc 'rsync -a /srv/src/ /srv/local-src/'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc 'git config -f /srv/local-src/config core.bare true'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc 'git config -f /srv/local-src/config --unset core.worktree || true'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc 'git config --global --add safe.directory /srv/local-src'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc '[ -d /srv/build ] || git clone /srv/local-src /srv/build'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc '(cd /srv/build && git pull --rebase)'
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc '[ -e /srv/build/config.log ] || (cd /srv/build && ./configure -C)' > $(DOCKER_STATE)/configure.${1}.${2} 2>&1

docker.${2}.${1}.test: docker.${2}.${1}.refresh
	$${Q}echo "TEST  $(DOCKER_IMAGE_PREFIX)-${2}-${1} > $(DOCKER_STATE)/test.${1}.${2}"
	$${Q}docker container exec $(DOCKER_IMAGE_PREFIX)-${2}-${1} sh -lc '(cd /srv/build && make && make test)' > $(DOCKER_STATE)/test.${1}.${2} 2>&1 || (echo FAIL ${1}.${2} && false)
endef


$(DOCKER_STATE):
	@mkdir -p $@

#
#  Build types, and the per-type knobs DOCKER_BUILD needs. Anything
#  type-specific (extra --build-arg, extra stamp deps) lives here so
#  the per-(image,type) wiring stays a plain double foreach.
#
#  $(IMG) in these values is resolved at $(eval) time inside the
#  foreach below, so each image sees its own substituted form.
#
#  Layer chain:
#    service          FROMs the upstream OS base (the m4 template's
#                     default ARG from=ubuntu:24.04 / debian:bookworm /
#                     rockylinux:9 etc.). Independent of crossbuild -
#                     it does its own apt-install of build deps.
#    profiling-deps   FROMs crossbuild/<image>:latest
#    profiling        FROMs profiling-deps/<image>:latest
#
#  The :latest base tags are published periodically by
#  docker-refresh.yml.
#
DOCKER_TYPES := ci crossbuild profiling-deps profiling service

DOCKER_BUILD_ARGS_service        :=
DOCKER_BUILD_ARGS_ci             :=
DOCKER_BUILD_ARGS_crossbuild      = $(if $(CB_FROM_$(IMG)),--build-arg=from=$(CB_FROM_$(IMG)))
DOCKER_BUILD_ARGS_profiling-deps  = --build-arg=from=$(DOCKER_IMAGE_PREFIX)-crossbuild/$(IMG):latest
DOCKER_BUILD_ARGS_profiling       = --build-arg=from=$(DOCKER_IMAGE_PREFIX)-profiling-deps/$(IMG):latest

DOCKER_BUILD_DEPS_service        :=
DOCKER_BUILD_DEPS_ci             :=
DOCKER_BUILD_DEPS_crossbuild     :=
DOCKER_BUILD_DEPS_profiling-deps  = $(DOCKER_STATE)/stamp-image.$(IMG).crossbuild
DOCKER_BUILD_DEPS_profiling       = $(DOCKER_STATE)/stamp-image.$(IMG).profiling-deps

#
#  Wire build + phony + clean + lifecycle + test for every (image,
#  type) combo.
#
$(foreach IMG,$(IMAGES), \
  $(foreach T,$(DOCKER_TYPES), \
    $(eval $(call DOCKER_BUILD,$(IMG),$(T),$(DOCKER_BUILD_ARGS_$(T)),$(DOCKER_BUILD_DEPS_$(T)))) \
    $(eval $(call DOCKER_PHONY,$(IMG),$(T))) \
    $(eval $(call DOCKER_CLEAN,$(IMG),$(T))) \
    $(eval $(call DOCKER_LIFECYCLE,$(IMG),$(T))) \
    $(eval $(call DOCKER_TEST,$(IMG),$(T)))))

#
#  Per-type umbrellas. .clean / .up / .down / .reset fan out to the
#  per-image variants; the bare docker.TYPE alias builds them all.
#
define DOCKER_TYPE_UMBRELLAS
.PHONY: docker.${1} docker.${1}.clean docker.${1}.up docker.${1}.down docker.${1}.reset
docker.${1}:       $(foreach IMG,${2},docker.${1}.$(IMG))
docker.${1}.clean: $(foreach IMG,${2},docker.${1}.$(IMG).clean)
docker.${1}.up:    $(foreach IMG,${2},docker.${1}.$(IMG).up)
docker.${1}.down:  $(foreach IMG,${2},docker.${1}.$(IMG).down)
docker.${1}.reset: $(foreach IMG,${2},docker.${1}.$(IMG).reset)
endef

$(foreach T,$(DOCKER_TYPES),$(eval $(call DOCKER_TYPE_UMBRELLAS,$(T),$(IMAGES))))

#
#  Across-type umbrellas. 'docker' is an alias for the service set.
#
.PHONY: docker docker.common docker.clean docker.up docker.down docker.reset docker.info docker.info_header
docker:        docker.info docker.service
docker.common: docker.info $(foreach IMG,$(DOCKER_COMMON),docker.service.$(IMG))

define DOCKER_VERB_UMBRELLA
docker.${1}: $(foreach T,$(DOCKER_TYPES),docker.$(T).${1})
endef

$(foreach V,clean up down reset,$(eval $(call DOCKER_VERB_UMBRELLA,$(V))))

docker.info: docker.info_header $(foreach IMG,$(IMAGES),docker.service.$(IMG).status)
	@echo All images: $(IMAGES)
	@echo Common images: $(DOCKER_COMMON)

docker.info_header:
	@echo Built images:

.PHONY: docker.help
docker.help:
	@echo ""
	@echo "Image builds ($(DOCKER_IMAGE_PREFIX)-TYPE/IMAGE:SHA):"
	@echo "    docker                            - build every service IMAGE (alias for docker.service)"
	@echo "    docker.common                     - build common service IMAGEs ($(DOCKER_COMMON))"
	@echo "    docker.info                       - list IMAGEs and their build status"
	@echo "    docker.TYPE                       - build every IMAGE of one TYPE"
	@echo "    docker.TYPE.IMAGE                 - build a single IMAGE"
	@echo "    docker.TYPE.IMAGE.status          - show whether the local IMAGE is built"
	@echo "    docker.TYPE.IMAGE.tag             - retag :latest as :SHA (no rebuild) so the current SHA resolves"
	@echo ""
	@echo "Container lifecycle (sleeping container, /srv/src bind-mounted from host git):"
	@echo "    docker.TYPE.IMAGE.up              - start container"
	@echo "    docker.TYPE.IMAGE.down            - stop container"
	@echo "    docker.TYPE.IMAGE.sh              - interactive shell in container"
	@echo "    docker.TYPE.IMAGE.log             - page the last build log"
	@echo "    docker.TYPE.IMAGE.reset           - rm stamps so the next build re-runs"
	@echo "    docker.TYPE.up                    - start a container for every IMAGE of one TYPE"
	@echo "    docker.TYPE.down                  - stop every container of one TYPE"
	@echo "    docker.TYPE.reset                 - rm stamps for every IMAGE of one TYPE"
	@echo "    docker.up                         - start a container for every (TYPE, IMAGE)"
	@echo "    docker.down                       - stop every container across every TYPE"
	@echo "    docker.reset                      - rm stamps for every IMAGE, every TYPE"
	@echo ""
	@echo "Cleanup (removes the docker IMAGE + stamp; IMAGE-in-use is a no-op):"
	@echo "    docker.clean                      - remove every locally-built IMAGE"
	@echo "    docker.TYPE.clean                 - remove every IMAGE of one TYPE"
	@echo "    docker.TYPE.IMAGE.clean           - remove a single IMAGE"
	@echo ""
	@echo "Test cycle (configure + make + make test inside a running container):"
	@echo "    docker.TYPE.IMAGE.refresh         - rsync src + git pull inside the container"
	@echo "    docker.TYPE.IMAGE.test            - run configure + make + make test in container"
	@echo ""
	@echo "Run 'make crossbuild.help' for the legacy crossbuild.* command aliases."
	@echo ""
	$(DOCKER_HELP_TYPES)
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"
	@echo "Run 'make dockerfile.help' for Dockerfile generation targets."

endif
