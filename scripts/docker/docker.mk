#
#  Docker targets to create Docker images that run FreeRADIUS
#
ifeq ($(shell which docker 2> /dev/null),)
.PHONY: docker docker.help
docker docker.help :
	@echo docker targets require Docker to be installed
else

#
#  Short list of common builds
#
DOCKER_COMMON:=ubuntu22

# Top level of where all crossbuild and docker files are. Strip the
# trailing slash that $(dir ...) leaves, and the leading project-root
# prefix so the path is relative -- shorter command lines, friendlier
# log output, and `docker build` still resolves it against CWD.
CB_DIR:=$(patsubst $(CURDIR)/%,%,$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST))))))

# Where the docker directories are
DT:=$(CB_DIR)/build

# Where stamp files and per-build logs land. Shared with crossbuild.mk
# so the periodic prune workflow only has one tree to look at.
DD:=$(CB_DIR)/crossbuild

# Location of top-level m4 template
DOCKERFILE_TMPL:=$(CB_DIR)/m4/Dockerfile.m4

# Shared m4 snippets included by every content template. Changes here
# invalidate every generated Dockerfile.
DOCKERFILE_M4_SHARED:=$(wildcard $(CB_DIR)/m4/common.*.m4) $(wildcard $(CB_DIR)/m4/_*.m4)

# List of all the docker images (sorted for "docker.info")
IMAGES:=$(sort $(patsubst $(DT)/%,%,$(wildcard $(DT)/*)))

# Don't use the Docker cache if asked
ifneq "$(NOCACHE)" ""
    DOCKER_BUILD_OPTS += " --no-cache"
endif

#
#  This Makefile is included in-line, and not via the "boilermake"
#  wrapper.  But it's still useful to use the same process for
#  seeing commands that are run.
#
ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif

include $(CB_DIR)/m4-macros.mk

#
#  Enter here: This builds everything
#
.PHONY: docker docker.common
docker:        docker.info $(foreach IMG,${IMAGES},docker.service.${IMG})
docker.common: docker.info $(foreach IMG,${DOCKER_COMMON},docker.service.${IMG})

#
#  Dump out some useful information on what images we're going to test
#
.PHONY: docker.info docker.info_header docker.help dockerfile.help
docker.info: docker.info_header $(foreach IMG,${IMAGES},docker.service.${IMG}.status)
	@echo All images: $(IMAGES)
	@echo Common images: $(DOCKER_COMMON)

docker.info_header:
	@echo Built images:

#
#  Glossary of type identifiers, shared by docker.help and
#  dockerfile.help so each can be read standalone without bouncing
#  to the other for the meaning of "service" / "ci" / etc.
#
define DOCKER_HELP_TYPES
	@echo "Types:"
	@echo "    service     production runtime image"
	@echo "    ci          slim toolchain base for ci-deb.yml / ci-rpm.yml"
	@echo "    crossbuild  full toolchain for crossbuild.yml (see 'make crossbuild.help')"
	@echo "    profiling   ubuntu24-only, layered on the crossbuild image"
endef

dockerfile.help:
	@echo ""
	@echo "Dockerfile generation (m4 templates -> scripts/docker/build/IMAGE/Dockerfile.TYPE):"
	@echo "    dockerfile                        - regenerate every Dockerfile across every type"
	@echo "    dockerfile.check                  - fail if any Dockerfile is stale"
	@echo "    dockerfile.TYPE                   - regenerate every Dockerfile of one type"
	@echo "    dockerfile.TYPE.check             - fail if any Dockerfile of one type is stale"
	@echo ""
	$(DOCKER_HELP_TYPES)

docker.help:
	@echo ""
	@echo "Image builds ($(DOCKER_IMAGE_PREFIX)-TYPE/IMAGE:SHA):"
	@echo "    docker                            - build all service images (alias for docker.service)"
	@echo "    docker.common                     - build common service images ($(DOCKER_COMMON))"
	@echo "    docker.info                       - list images and their build status"
	@echo "    docker.TYPE                       - build every image of one type"
	@echo "    docker.TYPE.IMAGE                 - build a single image"
	@echo "    docker.TYPE.IMAGE.status          - show whether the local image is built"
	@echo ""
	@echo "Cleanup (removes the docker image + stamp; image-in-use is a no-op):"
	@echo "    docker.clean                      - remove every locally-built image"
	@echo "    docker.TYPE.clean                 - remove every image of one type"
	@echo "    docker.TYPE.IMAGE.clean           - remove a single image"
	@echo ""
	$(DOCKER_HELP_TYPES)
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"
	@echo "Run 'make dockerfile.help' for Dockerfile generation targets."

#
#  Per-image m4 -> Dockerfile.<type> regen rules and stamp-tracked
#  build rules, plus bundle / drift-detector targets per type.
#
$(foreach IMG,$(IMAGES),\
  $(eval $(call DOCKERFILE_RULE,$(IMG),service,$(CB_DIR)/m4/service.deb.m4 $(CB_DIR)/m4/service.rpm.m4)) \
  $(eval $(call DOCKERFILE_RULE,$(IMG),ci,$(CB_DIR)/m4/ci.deb.m4 $(CB_DIR)/m4/ci.rpm.m4)) \
  $(eval $(call DOCKER_BUILD,$(IMG),service,,)) \
  $(eval $(call DOCKER_BUILD,$(IMG),ci,,)) \
  $(eval $(call DOCKER_PHONY,$(IMG),service)) \
  $(eval $(call DOCKER_PHONY,$(IMG),ci)) \
  $(eval $(call DOCKER_CLEAN,$(IMG),service)) \
  $(eval $(call DOCKER_CLEAN,$(IMG),ci)))

$(eval $(call DOCKERFILE_ALL,dockerfile.service,service,$(IMAGES)))
$(eval $(call DOCKERFILE_ALL,dockerfile.ci,ci,$(IMAGES)))
$(eval $(call DOCKERFILE_CHECK,dockerfile.service.check,service,$(IMAGES),dockerfile.service))
$(eval $(call DOCKERFILE_CHECK,dockerfile.ci.check,ci,$(IMAGES),dockerfile.ci))

#
#  Umbrellas across the whole image set.
#
.PHONY: docker.service docker.ci docker.service.clean docker.ci.clean
docker.service:       $(foreach IMG,$(IMAGES),docker.service.$(IMG))
docker.ci:            $(foreach IMG,$(IMAGES),docker.ci.$(IMG))
docker.service.clean: $(foreach IMG,$(IMAGES),docker.service.$(IMG).clean)
docker.ci.clean:      $(foreach IMG,$(IMAGES),docker.ci.$(IMG).clean)

#
#  Regenerate every Dockerfile.<type> across every image (or fail
#  the check across the lot). crossbuild / profiling come from
#  crossbuild.mk, which loads alongside docker.mk.
#
.PHONY: dockerfile dockerfile.check
dockerfile:       dockerfile.ci       dockerfile.crossbuild       dockerfile.profiling       dockerfile.service
dockerfile.check: dockerfile.ci.check dockerfile.crossbuild.check dockerfile.profiling.check dockerfile.service.check

#
#  Wipe every locally-built image (and its stamp) across every type.
#  Each per-image clean only nukes its stamp if the docker rmi
#  succeeded; this umbrella inherits that behaviour.
#
.PHONY: docker.clean
docker.clean: docker.ci.clean docker.crossbuild.clean docker.profiling.clean docker.service.clean


# if docker is defined
endif
