#
#  Legacy `crossbuild.*` command surface. Predates the unified
#  docker.<type>.<image>.<verb> shape and is kept here as a thin
#  alias layer over the new targets, so existing CI invocations
#  and muscle memory keep working.
#

ifndef CROSSBUILD_MK_INCLUDED
CROSSBUILD_MK_INCLUDED := 1

include scripts/docker/docker.mk

# Short list of common-case crossbuild images used by `make crossbuild`.
CB_COMMON := rocky9 debian12 ubuntu24

#
#  Per-image alias macro. .clean and .distclean keep their old
#  semantics rather than tracking the new naming:
#    crossbuild.IMAGE.clean     = down container + rm stamps (no rmi)
#    crossbuild.IMAGE.distclean = rmi + rm stamps (the full nuke,
#                                 which the new docker.crossbuild.IMAGE.clean does)
#
define CROSSBUILD_ALIASES
.PHONY: crossbuild.${1} \
        crossbuild.${1}.status   crossbuild.${1}.up        crossbuild.${1}.down \
        crossbuild.${1}.sh       crossbuild.${1}.log       crossbuild.${1}.refresh \
        crossbuild.${1}.reset    crossbuild.${1}.clean     crossbuild.${1}.distclean

crossbuild.${1}:           docker.crossbuild.${1}.test
crossbuild.${1}.status:    docker.crossbuild.${1}.status
crossbuild.${1}.up:        docker.crossbuild.${1}.up
crossbuild.${1}.down:      docker.crossbuild.${1}.down
crossbuild.${1}.sh:        docker.crossbuild.${1}.sh
crossbuild.${1}.log:       docker.crossbuild.${1}.log
crossbuild.${1}.refresh:   docker.crossbuild.${1}.refresh
crossbuild.${1}.reset:     docker.crossbuild.${1}.reset
crossbuild.${1}.clean:     docker.crossbuild.${1}.down docker.crossbuild.${1}.reset
crossbuild.${1}.distclean: docker.crossbuild.${1}.clean
endef

$(foreach IMG,$(IMAGES),$(eval $(call CROSSBUILD_ALIASES,$(IMG))))

#
#  Umbrellas across the crossbuild image set.
#
.PHONY: crossbuild crossbuild.common crossbuild.down crossbuild.reset \
        crossbuild.clean crossbuild.distclean crossbuild.info crossbuild.info_header \
        crossbuild.help

crossbuild:           $(foreach IMG,$(IMAGES),crossbuild.$(IMG))
crossbuild.common:    $(foreach IMG,$(CB_COMMON),crossbuild.$(IMG))
crossbuild.down:      docker.crossbuild.down
crossbuild.reset:     docker.crossbuild.reset
crossbuild.clean:     docker.crossbuild.down docker.crossbuild.reset
crossbuild.distclean: docker.crossbuild.clean

crossbuild.info: crossbuild.info_header $(foreach IMG,$(IMAGES),crossbuild.$(IMG).status)
	@echo Common images: $(CB_COMMON)

crossbuild.info_header:
	@echo Crossbuild images:

crossbuild.help:
	@echo ""
	@echo "Legacy crossbuild.* aliases (prefer the docker.crossbuild.* targets):"
	@echo "    crossbuild                        - run the test cycle for every IMAGE"
	@echo "    crossbuild.common                 - run the test cycle for $(CB_COMMON)"
	@echo "    crossbuild.info                   - list IMAGEs and their state"
	@echo "    crossbuild.down                   - stop every container"
	@echo "    crossbuild.reset                  - rm stamps for every IMAGE"
	@echo "    crossbuild.clean                  - down + reset across every IMAGE"
	@echo "    crossbuild.distclean              - rmi + rm stamps across every IMAGE"
	@echo ""
	@echo "Per-IMAGE legacy aliases (all map to docker.crossbuild.IMAGE.<verb>):"
	@echo "    crossbuild.IMAGE                  - run the test cycle for one IMAGE"
	@echo "    crossbuild.IMAGE.status           - show built / running state"
	@echo "    crossbuild.IMAGE.up               - start container"
	@echo "    crossbuild.IMAGE.down             - stop container"
	@echo "    crossbuild.IMAGE.sh               - shell in container"
	@echo "    crossbuild.IMAGE.log              - page latest build log"
	@echo "    crossbuild.IMAGE.refresh          - rsync src + git pull inside container"
	@echo "    crossbuild.IMAGE.reset            - rm stamps for one IMAGE"
	@echo "    crossbuild.IMAGE.clean            - down + reset for one IMAGE"
	@echo "    crossbuild.IMAGE.distclean        - rmi + rm stamps for one IMAGE"
	@echo ""
	@echo "Run 'make docker.help' for the unified docker.<type>.<image>.<verb> targets."

endif
