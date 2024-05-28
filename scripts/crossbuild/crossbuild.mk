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
CB_COMMON:=centos7 rocky9 debian11 ubuntu20

# Where to put stamp files (subdirectory of where this makefile is)
CB_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# Where the docker directories are
DT:=$(CB_DIR)/docker

# Where to put stamp files (subdirectory of where this makefile is)
DD:=$(CB_DIR)/build

# Location of top-level m4 template
DOCKER_TMPL:=$(CB_DIR)/../docker/m4/Dockerfile.m4

# List of all the docker images (sorted for "crossbuild.info")
CB_IMAGES:=$(sort $(patsubst $(DT)/%,%,$(wildcard $(DT)/*)))

# Location of the .git dir (may be different for e.g. submodules)
GITDIR:=$(shell perl -MCwd -e 'print Cwd::abs_path shift' $$(git rev-parse --git-dir))

CB_CPREFIX:=fr-crossbuild-
CB_IPREFIX:=freeradius-build

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
	@echo "    crossbuild               - build and test all images"
	@echo "    crossbuild.common        - build and test common images"
	@echo "    crossbuild.info          - list images"
	@echo "    crossbuild.down          - stop all containers"
	@echo "    crossbuild.reset         - remove cache of docker state"
	@echo "    crossbuild.clean         - down and reset all targets"
	@echo "    crossbuild.wipe          - destroy all crossbuild Docker images"
	@echo ""
	@echo "Per-image targets:"
	@echo "    crossbuild.IMAGE         - build and test image <IMAGE>"
	@echo "    crossbuild.IMAGE.log     - show latest build log"
	@echo "    crossbuild.IMAGE.up      - start container"
	@echo "    crossbuild.IMAGE.down    - stop container"
	@echo "    crossbuild.IMAGE.sh      - shell in container"
	@echo "    crossbuild.IMAGE.refresh - push latest commits into container"
	@echo "    crossbuild.IMAGE.reset   - remove cache of docker state"
	@echo "    crossbuild.IMAGE.clean   - stop container and tidy up"
	@echo "    crossbuild.IMAGE.wipe    - remove Docker image"

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
crossbuild.wipe: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.wipe)

#
#  Regenerate all Dockerfiles from m4 templates
#
crossbuild.regen: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.regen)

#
#  Define rules for building a particular image
#
define CROSSBUILD_IMAGE_RULE
#
#  Show status (based on stamp files)
#
.PHONY: crossbuild.${1}.status
crossbuild.${1}.status:
	${Q}printf "%s" "`echo \"  ${1}                    \" | cut -c 1-20`"
	${Q}if [ -e "$(DD)/stamp-up.${1}" ]; then echo "running"; \
		elif [ -e "$(DD)/stamp-image.${1}" ]; then echo "built"; \
		else echo "-"; fi
#
#  Build the docker image
#
$(DD)/stamp-image.${1}:
	${Q}echo "BUILD ${1} ($(CB_IPREFIX)/${1}) > $(DD)/build.${1}"
	${Q}docker build $(DOCKER_BUILD_OPTS) $(DT)/${1} -f $(DT)/${1}/Dockerfile -t $(CB_IPREFIX)/${1} >$(DD)/build.${1} 2>&1
	${Q}touch $(DD)/stamp-image.${1}

#
#  Start up the docker container
#
.PHONY: $(DD)/docker.up.${1}
$(DD)/docker.up.${1}: $(DD)/stamp-image.${1}
	${Q}echo "START ${1} ($(CB_CPREFIX)${1})"
	${Q}docker container inspect $(CB_CPREFIX)${1} >/dev/null 2>&1 || \
		docker run -d --rm \
		--privileged --cap-add=ALL \
		--mount=type=bind,source="$(GITDIR)",destination=/srv/src,ro \
		--name $(CB_CPREFIX)${1} $(CB_IPREFIX)/${1} \
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
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c 'rsync -a /srv/src/ /srv/local-src/'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c 'git config --global --add safe.directory /srv/local-src'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c 'git config -f /srv/local-src/config core.bare true'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c 'git config -f /srv/local-src/config --unset core.worktree || true'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c '[ -d /srv/build ] || git clone /srv/local-src /srv/build'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c '(cd /srv/build && git pull --rebase)'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c '[ -e /srv/build/config.log ] || echo CONFIGURE ${1}'
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c '[ -e /srv/build/config.log ] || (cd /srv/build && ./configure -C)' > $(DD)/configure.${1} 2>&1

.PHONY: $(DD)/docker.run.${1}
$(DD)/docker.run.${1}: $(DD)/docker.refresh.${1}
	${Q}echo "TEST ${1} > $(DD)/log.${1}"
	${Q}docker container exec $(CB_CPREFIX)${1} sh -c '(cd /srv/build && make && make test)' > $(DD)/log.${1} 2>&1 || echo FAIL ${1}

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
		less +G $(DD)/log.${1};\
	elif which more >/dev/null; then \
		more $(DD)/log.${1};\
	else cat $(DD)/log.${1}; fi

#
#  Tidy up stamp files. This means on next run we'll do
#  everything. Required if e.g. system has been rebooted, so
#  containers are stopped, but the stamp file still exists.
#
.PHONY: crossbuild.${1}.reset
crossbuild.${1}.reset:
	${Q}echo RESET ${1}
	${Q}rm -f $(DD)/stamp-up.${1}
	${Q}rm -f $(DD)/stamp-image.${1}

#
#  Clean down images. Means on next run we'll rebuild the
#  container (rather than just starting it).
#
.PHONY: crossbuild.${1}.wipe
crossbuild.${1}.wipe:
	${Q}echo CLEAN ${1}
	${Q}docker image rm $(CB_IPREFIX)/${1} >/dev/null 2>&1 || true
	${Q}rm -f $(DD)/stamp-image.${1}

#
#  Refresh git repository within the docker image
#
.PHONY: crossbuild.${1}.refresh
crossbuild.${1}.refresh: $(DD)/docker.refresh.${1}

#
#  Regenerate the image Dockerfile from the m4 templates
#
.PHONY: crossbuild.${1}.regen
crossbuild.${1}.regen: $(DT)/${1}/Dockerfile

$(DT)/${1}/Dockerfile: $(DOCKER_TMPL) $(CB_DIR)/m4/Dockerfile.deb.m4 $(CB_DIR)/m4/Dockerfile.rpm.m4
	${Q}echo REGEN ${1}
	${Q}m4 -I $(CB_DIR)/m4 -D D_NAME=${1} -D D_TYPE=crossbuild $$< > $$@

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
