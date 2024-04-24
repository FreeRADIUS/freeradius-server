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

# Top level of where all crossbuild and docker files are
CB_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# Where the docker directories are
DT:=$(CB_DIR)/build

# Location of top-level m4 template
DOCKER_TMPL:=$(CB_DIR)/m4/Dockerfile.m4

# List of all the docker images (sorted for "docker.info")
IMAGES:=$(sort $(patsubst $(DT)/%,%,$(wildcard $(DT)/*)))

# Don't use the Docker cache if asked
ifneq "$(NOCACHE)" ""
    DOCKER_BUILD_OPTS += " --no-cache"
endif

# Docker image name prefix
D_IPREFIX:=freeradius4

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

#
#  Enter here: This builds everything
#
.PHONY: docker docker.common
docker: docker.info $(foreach IMG,${IMAGES},docker.${IMG})
docker.common: docker.info $(foreach IMG,${DOCKER_COMMON},docker.${IMG})

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
	@echo "    docker                   - build all images"
	@echo "    docker.common            - build and test common images"
	@echo "    docker.info              - list images"
	@echo "    docker.regen             - regenerate all Dockerfiles"
	@echo ""
	@echo "Per-image targets:"
	@echo "    docker.IMAGE.build       - build image as $(D_IPREFIX)/<IMAGE>"
	@echo "    docker.IMAGE.regen       - regenerate Dockerfile from template"
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"

#
#  Regenerate all Dockerfiles from m4 templates
#
docker.regen: $(foreach IMG,${IMAGES},docker.${IMG}.regen)

#
#  Define rules for building a particular image
#
define CROSSBUILD_IMAGE_RULE

.PHONY: docker.${1}.status
docker.${1}.status:
	${Q}docker image ls --format "\t{{.Repository}} \t{{.CreatedAt}}" $(D_IPREFIX)/${1}

#
#  Build the docker image
#
.PHONY: docker.${1}.build
docker.${1}.build:
	${Q}echo "BUILD ${1} ($(D_IPREFIX)/${1}) from $(DT)/${1}/Dockerfile"

	${Q}docker buildx build \
		$(DOCKER_BUILD_OPTS) \
		--progress=plain \
		. \
		-f $(DT)/${1}/Dockerfile \
		-t $(D_IPREFIX)/${1}

#
#  Regenerate the image Dockerfile from the m4 templates
#
.PHONY: docker.${1}.regen
docker.${1}.regen: $(DT)/${1}/Dockerfile

$(DT)/${1}/Dockerfile: $(DOCKER_TMPL) $(CB_DIR)/m4/docker.deb.m4 $(CB_DIR)/m4/docker.rpm.m4
	${Q}echo REGEN ${1} "->" $$@
	${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=docker $$< > $$@

endef

#
#  Add all the image building rules
#
$(foreach IMAGE,$(IMAGES),\
  $(eval $(call CROSSBUILD_IMAGE_RULE,$(IMAGE))))


# if docker is defined
endif
