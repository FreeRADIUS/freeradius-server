#
#  Docker-related targets
#
#  Intended for internal use to publish Docker images to docker hub. Likely need to run
#  "docker login" before any push commands.
#
#  Examples:
#
#  Publish to Dockerhub "freeradius-server"
#    make DOCKER_VERSION=3.0.20 DOCKER_BUILD_ARGS="--no-cache" docker-publish
#
#  Build and push "freeradius-dev" image to Dockerhub (e.g. CI on every commit):
#    make DOCKER_VERSION=latest DOCKER_COMMIT=v3.0.x DOCKER_TAG="freeradius-dev" DOCKER_BUILD_ARGS="--no-cache" docker-push
#
#  Push to local repository:
#    make DOCKER_VERSION=3.0.20 DOCKER_TAG="our-freeradius-build" DOCKER_REGISTRY="docker.somewhere.example" docker-publish
#
#  See what is going to happen:
#    make Q=": " ...
#
#
#  Variables:
#
#  Which version to tag as, e.g. "3.0.20". If this is not an actual release
#  version, DOCKER_COMMIT _must_ also be set.
DOCKER_VERSION := $(RADIUSD_VERSION_STRING)
#
#  Commit hash/tag/branch to build, will be taken from VERSION above if not overridden, e.g. "release_3_0_20"
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

ifneq "$(DOCKER_REPO)" ""
	override DOCKER_REPO := $(DOCKER_REPO)/
endif

ifneq "$(DOCKER_REGISTRY)" ""
	override DOCKER_REGISTRY := $(DOCKER_REGISTRY)/
endif


.PHONY: docker
docker:
	@echo Building $(DOCKER_COMMIT)
	$(Q)docker build $(DOCKER_BUILD_ARGS) scripts/docker/ubuntu18 --build-arg=release=$(DOCKER_COMMIT) -t $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)
	$(Q)docker build $(DOCKER_BUILD_ARGS) scripts/docker/alpine --build-arg=release=$(DOCKER_COMMIT) -t $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker-push
docker-push: docker
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine

.PHONY: docker-tag-latest
docker-tag-latest: docker
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION) $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker tag $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):$(DOCKER_VERSION)-alpine $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine

.PHONY: docker-push-latest
docker-push-latest: docker-push docker-tag-latest
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest
	$(Q)docker push $(DOCKER_REGISTRY)$(DOCKER_REPO)$(DOCKER_TAG):latest-alpine

.PHONY: docker-publish
docker-publish: docker-push-latest
