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
	@echo "    docker                   - build all images"
	@echo "    docker.common            - build and test common images"
	@echo "    docker.info              - list images"
	@echo "    docker.regen             - regenerate all production Dockerfiles"
	@echo "    ci-base.regen            - regenerate all CI base Dockerfile.ci files"
	@echo ""
	@echo "Per-image targets:"
	@echo "    docker.IMAGE.build       - build image as $(D_IPREFIX)/<IMAGE>"
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"

#
#  Regenerate all Dockerfiles from m4 templates. Both bundles depend
#  on the file targets directly; no per-image phony aliases.
#
.PHONY: docker.regen ci-base.regen docker.regen.check ci-base.regen.check
docker.regen: $(foreach IMG,${IMAGES},$(DT)/${IMG}/Dockerfile)
ci-base.regen: $(foreach IMG,${IMAGES},$(DT)/${IMG}/Dockerfile.ci)

#
#  Verify every committed Dockerfile / Dockerfile.ci matches a fresh
#  render of its m4 source. Fails with a diff if a contributor edited
#  the m4 but forgot to regen+commit.
#
docker.regen.check:
	@failed=0; for IMG in $(IMAGES); do \
		tmp=$$(mktemp); \
		m4 -I $(CB_DIR)/m4 -D D_NAME=$$IMG -D D_TYPE=docker $(DOCKER_TMPL) > $$tmp; \
		if ! diff -u $(DT)/$$IMG/Dockerfile $$tmp; then \
			echo "OUT OF SYNC: $(DT)/$$IMG/Dockerfile"; failed=1; \
		fi; \
		rm $$tmp; \
	done; \
	[ $$failed -eq 0 ] || { echo; echo "Run 'make docker.regen' and commit the result."; exit 1; }

ci-base.regen.check:
	@failed=0; for IMG in $(IMAGES); do \
		tmp=$$(mktemp); \
		m4 -I $(CB_DIR)/m4 -D D_NAME=$$IMG -D D_TYPE=ci-base $(DOCKER_TMPL) > $$tmp; \
		if ! diff -u $(DT)/$$IMG/Dockerfile.ci $$tmp; then \
			echo "OUT OF SYNC: $(DT)/$$IMG/Dockerfile.ci"; failed=1; \
		fi; \
		rm $$tmp; \
	done; \
	[ $$failed -eq 0 ] || { echo; echo "Run 'make ci-base.regen' and commit the result."; exit 1; }

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
#  Production image Dockerfile rule. The CI base Dockerfile.ci is
#  consumed by docker-refresh.yml to build the self-hosted-* base
#  images that ci-deb.yml / ci-rpm.yml run their build jobs inside.
#  Both regen via the bundle targets above; no per-image variants.
#
$(DT)/${1}/Dockerfile: $(DOCKER_TMPL) $(CB_DIR)/m4/docker.deb.m4 $(CB_DIR)/m4/docker.rpm.m4 $(M4_SHARED)
	${Q}echo REGEN ${1} "->" $$@
	${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=docker $$< > $$@

$(DT)/${1}/Dockerfile.ci: $(DOCKER_TMPL) $(CB_DIR)/m4/ci-base.deb.m4 $(CB_DIR)/m4/ci-base.rpm.m4 $(M4_SHARED)
	${Q}echo REGEN ${1} "->" $$@
	${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=ci-base $$< > $$@

endef

#
#  Add all the image building rules
#
$(foreach IMAGE,$(IMAGES),\
  $(eval $(call CROSSBUILD_IMAGE_RULE,$(IMAGE))))


# if docker is defined
endif
