#
#  Include crossbuild targets, to test building on lots of
#  different OSes. Uses Docker.
#
ifeq ($(shell which docker 2> /dev/null),)
.PHONY: crossbuild crossbuild.help
crossbuild crossbuild.help :
	@echo crossbuild requires Docker to be installed
else

#
#  Short list of common builds
#
CB_COMMON:=rocky9 debian12 ubuntu24

# Top level of where all crossbuild and docker files are. `$(dir ...)`
# would leave a trailing slash that doubles up when concatenated with
# `/build` etc., so strip it here once.
CB_DIR:=$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

# Where the docker directories are
DT:=$(CB_DIR)/build

# Where to put stamp files and logs
DD:=$(CB_DIR)/crossbuild

# Location of top-level m4 template
DOCKER_TMPL:=$(CB_DIR)/m4/Dockerfile.m4

# List of all the docker images (sorted for "crossbuild.info")
CB_IMAGES:=$(sort $(patsubst $(DT)/%,%,$(wildcard $(DT)/*)))

# Location of the .git dir (may be different for e.g. submodules)
GITDIR:=$(shell perl -MCwd -e 'print Cwd::abs_path shift' $$(git rev-parse --git-dir))

# Don't use the Docker cache if asked
ifneq "$(NOCACHE)" ""
    DOCKER_BUILD_OPTS += "--no-cache"
endif

# Docker container name prefix. Image tags now derive from type via
# DOCKER_BUILD (freeradius4-crossbuild/<image>:<sha>); the container
# name still has its own prefix because it has to be valid in
# `docker run --name` (no slashes / colons) and disambiguate from
# any service-image containers.
CB_CPREFIX:=fr40x-crossbuild-

# Shared m4 snippets included by every content template.
M4_SHARED:=$(wildcard $(CB_DIR)/m4/common.*.m4)

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
.PHONY: crossbuild crossbuild.common
crossbuild: crossbuild.info $(foreach IMG,${CB_IMAGES},crossbuild.${IMG})
crossbuild.common: crossbuild.info $(foreach IMG,${CB_COMMON},crossbuild.${IMG})

#
#  Dump out some useful information on what images we're going to test
#
.PHONY: crossbuild.info crossbuild.info_header crossbuild.help
crossbuild.info: crossbuild.info_header $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.status)
	@echo Common images: $(CB_COMMON)

crossbuild.info_header:
	@echo Images:

crossbuild.help: crossbuild.info
	@echo ""
	@echo "Make targets:"
	@echo "    crossbuild                    - build and test all images"
	@echo "    crossbuild.common             - build and test common images"
	@echo "    crossbuild.info               - list images"
	@echo "    crossbuild.down               - stop all containers"
	@echo "    crossbuild.reset              - remove cache of docker state"
	@echo "    crossbuild.clean              - down and reset all targets"
	@echo "    crossbuild.distclean          - destroy all crossbuild Docker images"
	@echo ""
	@echo "Per-image targets:"
	@echo "    crossbuild.IMAGE              - build and test image <IMAGE>"
	@echo "    crossbuild.IMAGE.log          - show latest build log"
	@echo "    crossbuild.IMAGE.up           - start container"
	@echo "    crossbuild.IMAGE.down         - stop container"
	@echo "    crossbuild.IMAGE.sh           - shell in container"
	@echo "    crossbuild.IMAGE.refresh      - push latest commits into container"
	@echo "    crossbuild.IMAGE.reset        - remove cache of docker state"
	@echo "    crossbuild.IMAGE.clean        - stop container and tidy up"
	@echo "    crossbuild.IMAGE.distclean    - remove Docker image"
	@echo ""
	@echo "Use 'make NOCACHE=1 ...' to disregard the Docker cache on build"

#
#  Remove stamp files, so that we try and create images again
#
crossbuild.reset: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.reset)

#
#  Stop all containers
#
crossbuild.down: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.down)

#
#  Clean up: stop all containers, do a reset
#
crossbuild.clean: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.clean)

#
#  Remove all images
#
crossbuild.distclean: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.distclean)

include $(CB_DIR)/m4-macros.mk

#
#  Per-image m4 -> Dockerfile.crossbuild regen rules and stamp-tracked
#  build rules, plus bundle and drift-detector targets.
#
$(foreach IMG,$(CB_IMAGES),\
  $(eval $(call M4_REGEN_RULE,$(IMG),crossbuild,$(CB_DIR)/m4/crossbuild.deb.m4 $(CB_DIR)/m4/crossbuild.rpm.m4)) \
  $(eval $(call DOCKER_BUILD,$(IMG),crossbuild,$(if $(CB_FROM_$(IMG)),--build-arg=from=$(CB_FROM_$(IMG))),)))

$(eval $(call M4_REGEN_BUNDLE,docker.crossbuild.regen,crossbuild,$(CB_IMAGES)))
$(eval $(call M4_REGEN_CHECK,docker.crossbuild.regen.check,crossbuild,$(CB_IMAGES),docker.crossbuild.regen))

#
#  Profiling image: ubuntu24-only extra layer on top of the crossbuild
#  image. There's no profiling.rpm.m4 (the dbgsym repo and apt-based
#  install steps are debian/ubuntu specific), so the regen+build are
#  filtered to ubuntu24 only. The image FROMs freeradius4-crossbuild/
#  ubuntu24:<sha>, so the build also depends on the crossbuild stamp.
#
PROFILING_IMAGES := $(filter ubuntu24,$(CB_IMAGES))

$(foreach IMG,$(PROFILING_IMAGES),\
  $(eval $(call M4_REGEN_RULE,$(IMG),profiling,$(CB_DIR)/m4/profiling.deb.m4)) \
  $(eval $(call DOCKER_BUILD,$(IMG),profiling,--build-arg=from=freeradius4-crossbuild/$(IMG):$(GIT_SHA),$(DD)/stamp-image.$(IMG).crossbuild)))

$(eval $(call M4_REGEN_BUNDLE,docker.profiling.regen,profiling,$(PROFILING_IMAGES)))
$(eval $(call M4_REGEN_CHECK,docker.profiling.regen.check,profiling,$(PROFILING_IMAGES),docker.profiling.regen))

.PHONY: docker.profiling.build
docker.profiling.build: $(foreach IMG,$(PROFILING_IMAGES),$(DD)/stamp-image.$(IMG).profiling)


#
#  Define rules for building a particular image. The stamp-image
#  file target and the Dockerfile.crossbuild target are generated by
#  DOCKER_BUILD / M4_REGEN_RULE above (see m4-macros.mk); this block
#  only defines the per-image lifecycle targets (status / up / down
#  / sh / refresh / log / reset / clean / distclean) that don't
#  generalise across types.
#
define CROSSBUILD_IMAGE_RULE

.PHONY: crossbuild.${1}.status
crossbuild.${1}.status:
	${Q}printf "%s" "`echo \"  ${1}                    \" | cut -c 1-20`"
	${Q}if [ -e "$(DD)/stamp-up.${1}" ]; then echo "running"; \
		elif [ -e "$(DD)/stamp-image.${1}.crossbuild" ]; then echo "built"; \
		else echo "-"; fi

#
#  Start up the docker container. CB_FROM_${1} overrides the `from`
#  build-arg via DOCKER_BUILD's macro arg; CI exports CB_FROM_<distro>
#  to point at internal base images (see .github/workflows/crossbuild.yml).
#
.PHONY: $(DD)/docker.up.${1}
$(DD)/docker.up.${1}: $(DD)/stamp-image.${1}.crossbuild
	${Q}echo "START ${1} ($(CB_CPREFIX)${1})"
	${Q}docker container inspect $(CB_CPREFIX)${1} >/dev/null 2>&1 || \
		docker run -d --rm \
		--privileged --cap-add=ALL \
		--mount=type=bind,source="$(GITDIR)",destination=/srv/src,ro \
		--name $(CB_CPREFIX)${1} freeradius4-crossbuild/${1}:$(GIT_SHA) \
		/bin/sh -c 'while true; do sleep 60; done' >/dev/null

$(DD)/stamp-up.${1}: $(DD)/docker.up.${1}
	${Q}touch $(DD)/stamp-up.${1}

.PHONY: crossbuild.${1}.up
crossbuild.${1}.up: $(DD)/stamp-up.${1}

#
#  Run tests in the container
#
.PHONY: $(DD)/docker.refresh.${1}
$(DD)/docker.refresh.${1}: $(DD)/stamp-up.${1}
	${Q}echo "REFRESH ${1}"
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc 'rsync -a /srv/src/ /srv/local-src/'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc 'git config -f /srv/local-src/config core.bare true'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc 'git config -f /srv/local-src/config --unset core.worktree || true'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc 'git config --global --add safe.directory /srv/local-src'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc '[ -d /srv/build ] || git clone /srv/local-src /srv/build'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc '(cd /srv/build && git pull --rebase)'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc '[ -e /srv/build/config.log ] || echo CONFIGURE ${1}'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc '[ -e /srv/build/config.log ] || (cd /srv/build && ./configure -C)' > $(DD)/configure.${1} 2>&1

.PHONY: $(DD)/docker.run.${1}
$(DD)/docker.run.${1}: $(DD)/docker.refresh.${1}
	${Q}echo "TEST ${1} > $(DD)/log.${1}"
	${Q}docker container exec $(CB_CPREFIX)${1} sh -lc '(cd /srv/build && make && make test)' > $(DD)/log.${1} 2>&1 || ( echo FAIL ${1} && false )

#
#  Stop the docker container
#
.PHONY: crossbuild.${1}.down
crossbuild.${1}.down:
	@echo STOP ${1}
	${Q}docker container kill $(CB_CPREFIX)${1} || true
	@rm -f $(DD)/stamp-up.${1}

.PHONY: crossbuild.${1}.clean
crossbuild.${1}.clean: crossbuild.${1}.down crossbuild.${1}.reset

#
#  Shell into container. cd to root first (will always succeed),
#  then try to change to build dir, which might not exist, then
#  run bash. (Default cwd is the wrong freeradius source in
#  /usr/local, which would be confusing)
#
.PHONY: crossbuild.${1}.sh
crossbuild.${1}.sh: crossbuild.${1}.up
	${Q}docker exec -it $(CB_CPREFIX)${1} sh -c 'cd / ; cd /srv/build 2>/dev/null; bash' || true

#
#  Show last build logs. Try and use the most sensible pager.
#
.PHONY: crossbuild.${1}.log
crossbuild.${1}.log:
	@if which less >/dev/null; then \
		less +G $(DD)/build.${1}.crossbuild;\
	elif which more >/dev/null; then \
		more $(DD)/build.${1}.crossbuild;\
	else cat $(DD)/build.${1}.crossbuild; fi

#
#  Tidy up stamp files. This means on next run we'll do
#  everything. Required if e.g. system has been rebooted, so
#  containers are stopped, but the stamp file still exists.
#
.PHONY: crossbuild.${1}.reset
crossbuild.${1}.reset:
	${Q}echo RESET ${1}
	${Q}rm -f $(DD)/stamp-up.${1}
	${Q}rm -f $(DD)/stamp-image.${1}.crossbuild

#
#  Clean down images. Means on next run we'll rebuild the
#  container (rather than just starting it).
#
.PHONY: crossbuild.${1}.distclean
crossbuild.${1}.distclean:
	${Q}echo CLEAN ${1}
	${Q}docker image rm freeradius4-crossbuild/${1}:$(GIT_SHA) >/dev/null 2>&1 || true
	${Q}rm -f $(DD)/stamp-image.${1}.crossbuild

#
#  Refresh git repository within the docker image
#
.PHONY: crossbuild.${1}.refresh
crossbuild.${1}.refresh: $(DD)/docker.refresh.${1}

#
#  Run the build test
#
.PHONY: crossbuild.${1}
crossbuild.${1}: $(DD)/docker.run.${1}

endef

#
#  Add all the image building rules
#
$(foreach IMAGE,$(CB_IMAGES),\
  $(eval $(call CROSSBUILD_IMAGE_RULE,$(IMAGE))))


# if docker is defined
endif
