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

# Top level of where all crossbuild and docker files are. `$(dir ...)`
# would leave a trailing slash that doubles up when concatenated with
# `/build` etc., so strip it here once.
CB_DIR:=$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

# Where the docker directories are
DT:=$(CB_DIR)/build

# Where stamp files and per-build logs land. Shared with crossbuild.mk
# so the periodic prune workflow only has one tree to look at.
DD:=$(CB_DIR)/crossbuild

# Location of top-level m4 template
DOCKER_TMPL:=$(CB_DIR)/m4/Dockerfile.m4

# Shared m4 snippets included by every content template. Changes here
# invalidate every generated Dockerfile.
M4_SHARED:=$(wildcard $(CB_DIR)/m4/common.*.m4)

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
docker: docker.info $(foreach IMG,${IMAGES},docker.${IMG}.build)
docker.common: docker.info $(foreach IMG,${DOCKER_COMMON},docker.${IMG}.build)

#
#  Dump out some useful information on what images we're going to test
#
.PHONY: docker.info docker.info_header docker.help
docker.info: docker.info_header $(foreach IMG,${IMAGES},docker.${IMG}.status)
	@echo All images: $(IMAGES)
	@echo Common images: $(DOCKER_COMMON)

docker.info_header:
	@echo Built images:

docker.help:
	@echo ""
	@echo "Make targets:"
	@echo "    docker                       - build all images"
	@echo "    docker.common                - build and test common images"
	@echo "    docker.info                  - list images"
	@echo "    docker.service.regen         - regenerate all Dockerfile.service files"
	@echo "    docker.ci.regen              - regenerate all Dockerfile.ci files"
	@echo "    docker.service.regen.check   - fail if any Dockerfile.service is stale"
	@echo "    docker.ci.regen.check        - fail if any Dockerfile.ci is stale"
	@echo ""
	@echo "Per-image targets:"
	@echo "    docker.IMAGE.build           - build image as freeradius4-service/<IMAGE>:$(GIT_SHA)"
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"

#
#  Per-image m4 -> Dockerfile.<type> regen rules and stamp-tracked
#  build rules, plus bundle / drift-detector targets per type.
#
$(foreach IMG,$(IMAGES),\
  $(eval $(call M4_REGEN_RULE,$(IMG),service,$(CB_DIR)/m4/service.deb.m4 $(CB_DIR)/m4/service.rpm.m4)) \
  $(eval $(call M4_REGEN_RULE,$(IMG),ci,$(CB_DIR)/m4/ci.deb.m4 $(CB_DIR)/m4/ci.rpm.m4)) \
  $(eval $(call DOCKER_BUILD,$(IMG),service,,)))

$(eval $(call M4_REGEN_BUNDLE,docker.service.regen,service,$(IMAGES)))
$(eval $(call M4_REGEN_BUNDLE,docker.ci.regen,ci,$(IMAGES)))
$(eval $(call M4_REGEN_CHECK,docker.service.regen.check,service,$(IMAGES),docker.service.regen))
$(eval $(call M4_REGEN_CHECK,docker.ci.regen.check,ci,$(IMAGES),docker.ci.regen))

#
#  Phony status / build wrappers for the per-image targets. The
#  stamp file (produced by DOCKER_BUILD) is the real work; the
#  phony just gives operators a stable name to type.
#
define DOCKER_SERVICE_PHONY
.PHONY: docker.${1}.status
docker.${1}.status:
	$${Q}docker image ls --format "\t{{.Repository}}:{{.Tag}} \t{{.CreatedAt}}" freeradius4-service/${1}

.PHONY: docker.${1}.build
docker.${1}.build: $(DD)/stamp-image.${1}.service
endef

$(foreach IMG,$(IMAGES),$(eval $(call DOCKER_SERVICE_PHONY,$(IMG))))


# if docker is defined
endif
