#
#  Docker-related targets
#
#  Intended for internal use to publish Docker images to docker hub. Likely need to run
#  "docker login" before any push commands.
#
#  Examples:
#
#  Publish to Dockerhub "freeradius-server"
#    make DOCKER_VERSION=3.2.0 DOCKER_BUILD_ARGS="--no-cache" docker-publish
#
#  Build and push "freeradius-dev" image to Dockerhub (e.g. CI on every commit):
#    make DOCKER_VERSION=latest DOCKER_COMMIT=v3.2.x DOCKER_TAG="freeradius-dev-3.2.x" DOCKER_BUILD_ARGS="--no-cache" docker-push
#
#  Push to local repository:
#    make DOCKER_VERSION=3.2.0 DOCKER_TAG="our-freeradius-build" DOCKER_REGISTRY="docker.somewhere.example" docker-publish
#
#  See what is going to happen:
#    make Q=": " ...
#
#
#  Variables:
#
#  Which version to tag as, e.g. "3.2.0". If this is not an actual release
#  version, DOCKER_COMMIT _must_ also be set.
DOCKER_VERSION := $(RADIUSD_VERSION_STRING)
#
#  Commit hash/tag/branch to build, if not set then HEAD will be used.
DOCKER_COMMIT :=
#
#  Build args, most likely "--no-cache"
DOCKER_BUILD_ARGS :=
#
#  Tag name, likely "freeradius-server" for releases, or "freeradius-dev" for nightlies.
DOCKER_TAG := freeradius-server
#
#  Repository name
DOCKER_REPO := freeradius
#
#  Registry to push to
DOCKER_REGISTRY :=
#
#  Location of Docker-related files
DOCKER_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DIST_DIR := $(DOCKER_DIR)/dists
#
#  List of images we can build
DOCKER_IMAGES:=$(sort $(patsubst $(DIST_DIR)/%,%,$(wildcard $(DIST_DIR)/*)))

DOCKER_DEFAULT_UBUNTU := ubuntu22
DOCKER_DEFAULT_ALPINE := alpine

ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif


ifneq "$(DOCKER_REPO)" ""
	override DOCKER_REPO := $(DOCKER_REPO)/
endif

ifneq "$(DOCKER_REGISTRY)" ""
	override DOCKER_REGISTRY := $(DOCKER_REGISTRY)/
endif


#
#  Print some useful help
#
.PHONY: docker.help.images
docker.help.images:
	@echo Available images: $(DOCKER_IMAGES)

.PHONY: docker.help
docker.help: docker.help.images
	@echo ""
	@echo "Make targets:"
	@echo "    docker-ubuntu        - build main ubuntu image"
	@echo "    docker-alpine        - build main alpine image"
	@echo "    docker.regen         - regenerate all Dockerfiles from templates"
	@echo ""
	@echo "Make targets per image:"
	@echo "    docker.IMAGE.build   - build image"
	@echo "    docker.IMAGE.regen   - regenerate Dockerfile"
	@echo ""
	@echo "Arguments:"
	@echo '    DOCKER_BUILD_ARGS="--no-cache"        - extra build args'
	@echo '    DOCKER_REGISTRY="docker.example.com"  - registry to build for'
	@echo '    DOCKER_REPO="freeradius"              - docker repo name'
	@echo '    DOCKER_TAG="freeradius-server"        - docker tag name'
	@echo '    DOCKER_COMMIT="HEAD"                  - commit/ref to build from'
	@echo '    DOCKER_VERSION="$(DOCKER_VERSION)"                - version for docker image name'


#
#  Rules for each OS
#

define ADD_DOCKER_RULES
    $$(DIST_DIR)/${1}/Dockerfile: $(DOCKER_DIR)/m4/Dockerfile.m4 $(DOCKER_DIR)/m4/Dockerfile.deb.m4 $(DOCKER_DIR)/m4/Dockerfile.rpm.m4 $(DOCKER_DIR)/m4/Dockerfile.alpine.m4 $(DOCKER_DIR)/docker.mk
	$$(Q)echo REGEN ${1}/Dockerfile
	$$(Q)m4 -I $(DOCKER_DIR)/m4 -D D_NAME=${1} -D D_TYPE=docker $$< > $$@

    DOCKER_DOCKERFILES += $$(DIST_DIR)/${1}/Dockerfile

    .PHONY: docker.${1}.regen
    docker.${1}.regen: $$(DIST_DIR)/${1}/Dockerfile

    .PHONY: docker.${1}.build
    docker.${1}.build:
	@echo BUILD ${1} $(DOCKER_COMMIT)
	$(Q)docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--progress=plain \
		--build-arg=release=$(DOCKER_COMMIT) \
		-t $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-${1} \
		-f $(DIST_DIR)/${1}/Dockerfile \
		.

endef

$(foreach IMAGE,$(DOCKER_IMAGES), \
  $(eval $(call ADD_DOCKER_RULES,$(IMAGE))))

.PHONY: docker.regen
docker.regen: $(DOCKER_DOCKERFILES)


#
#  Rules to rebuild Docker images
#
.PHONY: docker-ubuntu
docker-ubuntu: docker.$(DOCKER_DEFAULT_UBUNTU).build
	$(Q)docker image tag \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-$(DOCKER_DEFAULT_UBUNTU) \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)

.PHONY: docker-alpine
docker-alpine: docker.$(DOCKER_DEFAULT_ALPINE).build
	$(Q)docker image tag \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-$(DOCKER_DEFAULT_ALPINE) \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker
docker: docker-ubuntu docker-alpine

#
#  Push main ubuntu and alpine images (all below are separate for CI jobs)
#
.PHONY: docker-push-ubuntu
docker-push-ubuntu:
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)

.PHONY: docker-push-alpine
docker-push-alpine:
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker-push
docker-push: docker-push-ubuntu docker-push-alpine

#
#  Tag main "latest" images
#
.PHONY: docker-tag-latest-ubuntu
docker-tag-latest-ubuntu:
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2

.PHONY: docker-tag-latest-alpine
docker-tag-latest-alpine:
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2-alpine

.PHONY: docker-tag-latest
docker-tag-latest: docker-tag-latest-ubuntu docker-tag-latest-alpine

#
#  Push main "latest" images
#
.PHONY: docker-push-latest-ubuntu
docker-push-latest-ubuntu: docker-push-ubuntu docker-tag-latest-ubuntu
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2

.PHONY: docker-push-latest-alpine
docker-push-latest-alpine: docker-push-alpine docker-tag-latest-alpine
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2-alpine

.PHONY: docker-push-latest
docker-push-latest: docker-push-latest-ubuntu docker-push-latest-alpine

#
#  Convenience target to do everything
#
.PHONY: docker-publish
docker-publish: docker docker-push-latest

#
#  Used for multi-arch CI job. "docker manifest" rather than "docker buildx
#  --platforms=...,..." so that we can parallelise the build in GH Actions.
#
.PHONY: docker-ci-manifest
docker-ci-manifest:
	$(Q)docker manifest create \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) \
		$(foreach ARCH,$(DOCKER_ARCHS),--amend $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(ARCH)-$(DOCKER_VERSION))
	$(Q)docker manifest push \
		$(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)
