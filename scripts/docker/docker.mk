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
#  Commit hash/tag/branch to build, will be taken from VERSION above if not overridden, e.g. "release_3_2_0"
DOCKER_COMMIT := release_$(shell echo $(DOCKER_VERSION) | tr .- __)
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
#  Rules to regenerate Dockerfiles
#

define ADD_DOCKER_REGEN
    $$(DOCKER_DIR)/${1}/Dockerfile: $(DOCKER_DIR)/m4/Dockerfile.m4 $(DOCKER_DIR)/m4/Dockerfile.deb.m4 $(DOCKER_DIR)/m4/Dockerfile.rpm.m4 $(DOCKER_DIR)/docker.mk
	$$(Q)echo REGEN ${1}/Dockerfile
	$$(Q)m4 -I $(DOCKER_DIR)/m4 -D D_NAME=${1} -D D_TYPE=docker $$< > $$@

    DOCKER_DOCKERFILES += $$(DOCKER_DIR)/${1}/Dockerfile

    .PHONY: docker.${1}.regen
    docker.${1}.regen: $$(DOCKER_DIR)/${1}/Dockerfile
endef

$(eval $(call ADD_DOCKER_REGEN,debian10,deb,debian:buster,debian,10,buster))
$(eval $(call ADD_DOCKER_REGEN,debian11,deb,debian:bullseye,debian,11,bullseye))
$(eval $(call ADD_DOCKER_REGEN,debian12,deb,debian:bookworm,debian,12,bookworm))
$(eval $(call ADD_DOCKER_REGEN,ubuntu18,deb,ubuntu:18.04,ubuntu,18,bionic))
$(eval $(call ADD_DOCKER_REGEN,ubuntu20,deb,ubuntu:20.04,ubuntu,20,focal))
$(eval $(call ADD_DOCKER_REGEN,ubuntu22,deb,ubuntu:22.04,ubuntu,22,jammy))
$(eval $(call ADD_DOCKER_REGEN,centos7,rpm,centos:centos7,centos,7,7))
$(eval $(call ADD_DOCKER_REGEN,rocky8,rpm,rockylinux/rockylinux:8,rocky,8,8))
$(eval $(call ADD_DOCKER_REGEN,rocky9,rpm,rockylinux/rockylinux:9,rocky,9,9))

.PHONY: docker.regen
docker.regen: $(DOCKER_DOCKERFILES)


#
#  Rules to rebuild Docker images
#

.PHONY: docker-ubuntu
docker-ubuntu:
	@echo Building ubuntu $(DOCKER_COMMIT)
	$(Q)docker build $(DOCKER_BUILD_ARGS) scripts/docker/ubuntu22 --build-arg=release=$(DOCKER_COMMIT) -t $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)

.PHONY: docker-alpine
docker-alpine:
	@echo Building alpine $(DOCKER_COMMIT)
	$(Q)docker build $(DOCKER_BUILD_ARGS) scripts/docker/alpine --build-arg=release=$(DOCKER_COMMIT) -t $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker
docker: docker-ubuntu docker-alpine

.PHONY: docker-push
docker-push: docker
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker-tag-latest
docker-tag-latest: docker
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2-alpine

.PHONY: docker-push-latest
docker-push-latest: docker-push docker-tag-latest
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-3.2-alpine

.PHONY: docker-publish
docker-publish: docker-push-latest
