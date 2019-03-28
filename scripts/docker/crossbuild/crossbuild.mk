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
CB_COMMON:=centos7 debian9 ubuntu18

# Where the docker "build-" directories are
DT:=scripts/docker

# Location of this makefile, and where to put stamp files
DD:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# List of all the docker images
CB_IMAGES:=$(patsubst $(DT)/build-%,%,$(wildcard $(DT)/build-*))

CB_CPREFIX:=fr-crossbuild-
CB_IPREFIX:=freeradius-build

#
#  Enter here: This builds everything
#
.PHONY: crossbuild crossbuild.common
crossbuild: crossbuild.info $(foreach IMG,${CB_IMAGES},crossbuild.${IMG})
crossbuild.common: crossbuild.info $(foreach IMG,${CB_COMMON},crossbuild.${IMG})

#
#  Dump out some useful information on what images we're going to test
#
crossbuild.info:
	@echo Images:
	@for IMG in $(CB_IMAGES); do echo "    $$IMG"; done
	@echo Common images: $(CB_COMMON)

crossbuild.help: crossbuild.info
	@echo Make targets:
	@echo "    crossbuild             - build and test all images"
	@echo "    crossbuild.common      - build and test common images"
	@echo "    crossbuild.reset       - remove cache of docker state"
	@echo "    crossbuild.down        - stop all containers"
	@echo "    crossbuild.clean       - destroy all images"
	@echo "    crossbuild.IMAGE       - build and test IMAGE"
	@echo "    crossbuild.IMAGE.log   - show latest build log"
	@echo "    crossbuild.IMAGE.up    - start container"
	@echo "    crossbuild.IMAGE.down  - stop container"
	@echo "    crossbuild.IMAGE.sh    - shell in container"
	@echo "    crossbuild.IMAGE.clean - remove docker image"

#
#  Remove stamp files, so that we try and create images again
#
crossbuild.reset: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.reset)

#
#  Stop all containers
#
crossbuild.down: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.down)

#
#  Remove all images
#
crossbuild.clean: $(foreach IMG,${CB_IMAGES},crossbuild.${IMG}.clean)

#
#  Define rules for building a particular image
#
define CROSSBUILD_IMAGE_RULE
#
#  Build the docker image
#
$(DD)/stamp-image.${1}:
	@echo "BUILD ${1} ($(CB_IPREFIX)/${1}) > $(DD)/build.${1}"
	@docker build $(DT)/build-${1} -f $(DT)/build-${1}/Dockerfile.deps -t $(CB_IPREFIX)/${1} >$(DD)/build.${1} 2>&1
	@touch $(DD)/stamp-image.${1}

#
#  Start up the docker container
#
.PHONY: $(DD)/docker.up.${1}
$(DD)/docker.up.${1}: $(DD)/stamp-image.${1}
	@echo "START ${1} ($(CB_CPREFIX)${1})"
	@docker run -d --rm --name $(CB_CPREFIX)${1} $(CB_IPREFIX)/${1} /bin/sh -c 'while true; do sleep 60; done' >/dev/null 2>&1 || true

$(DD)/stamp-up.${1}: $(DD)/docker.up.${1}
	@touch $(DD)/stamp-up.${1}

.PHONY: crossbuild.${1}.up
crossbuild.${1}.up: $(DD)/stamp-up.${1}

#
#  Run tests in the container
#
.PHONY: $(DD)/docker.run.${1}
$(DD)/docker.run.${1}: $(DD)/stamp-up.${1}
	@echo "REFRESH ${1}"
	@docker container exec $(CB_CPREFIX)${1} [ ! -d /srv/src ] || rm -rf /srv/src
	@docker container exec $(CB_CPREFIX)${1} mkdir -p /srv/src
	@docker container cp .git $(CB_CPREFIX)${1}:/srv/src/
	@docker container exec $(CB_CPREFIX)${1} sh -c '[ -d /srv/build ] || git clone /srv/src /srv/build'
	@docker container exec $(CB_CPREFIX)${1} sh -c '(cd /srv/build && git pull --rebase)'
	@docker container exec $(CB_CPREFIX)${1} sh -c '[ -e /srv/build/config.log ] || echo CONFIGURE ${1}'
	@docker container exec $(CB_CPREFIX)${1} sh -c '[ -e /srv/build/config.log ] || (cd /srv/build && ./configure -C)' > $(DD)/configure.${1} 2>&1
	@echo "TEST ${1} > $(DD)/log.${1}"
	@docker container exec $(CB_CPREFIX)${1} sh -c '(cd /srv/build && make && make test)' > $(DD)/log.${1} 2>&1 || echo FAIL ${1}

#
#  Stop the docker container
#
.PHONY: crossbuild.${1}.down
crossbuild.${1}.down:
	@echo STOP ${1}
	@docker container kill $(CB_CPREFIX)${1} || true
	@rm -f $(DD)/stamp-up.${1}

#
#  Shell into container. cd to root first (will always succeed),
#  then try to change to build dir, which might not exist, then
#  run bash. (Default cwd is the wrong freeradius source in
#  /usr/local, which would be confusing)
#
.PHONY: crossbuild.${1}.sh
crossbuild.${1}.sh:
	@docker exec -it $(CB_CPREFIX)${1} sh -c 'cd / ; cd /srv/build 2>/dev/null; bash' || true

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
	@echo RESET ${1}
	@rm -f $(DD)/stamp-up.${1}
	@rm -f $(DD)/stamp-image.${1}

#
#  Clean down images. Means on next run we'll rebuild the
#  container (rather than just starting it).
#
.PHONY: crossbuild.${1}.clean
crossbuild.${1}.clean:
	@echo CLEAN ${1}
	@docker image rm $(CB_IPREFIX)/${1} >/dev/null 2>&1 || true
	@rm -f $(DD)/stamp-image.${1}

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
