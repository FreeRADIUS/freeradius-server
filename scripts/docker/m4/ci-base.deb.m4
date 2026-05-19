ARG from=DOCKER_IMAGE
FROM ${from}

ENV DEBIAN_FRONTEND=noninteractive

include(`common.apt.retries.m4')dnl
include(`common.deb.toolchain.m4')dnl

#
#  Extras the CI base needs on top of the common toolchain. libnl deps
#  feed the eapol_test build; xz-utils feeds the tmate debug step; file
#  is occasionally invoked from debian/rules.
#
#  Note: scripts/ci/extra-packages.debian.control is intentionally NOT
#  consumed here. That file is for the self-hosted-ubuntu24 integration
#  testbed (dovecot, freetds, firebird, etc.) and several of its entries
#  don't exist on older ubuntu/debian releases. The deb-build job only
#  needs debian/control's closure plus libnl for eapol_test.
#
RUN apt-get install -y --no-install-recommends \
		file \
		libnl-3-dev \
		libnl-genl-3-dev \
		xz-utils

include(`common.deb.nr-extras.m4')dnl

#
#  Pre-install the build-dep closure derived from debian/control. The
#  source-tree debian/ subtree is baked in at image-build time; ci-deb.yml
#  still runs mk-build-deps per job as a top-up so newly added deps are
#  picked up without an image rebuild.
#
COPY debian/ /tmp/freeradius-build/debian/
RUN cd /tmp/freeradius-build && \
	touch -t 202001010000 debian/control && \
	debian/rules debian/control && \
	mk-build-deps -irt"apt-get -y --no-install-recommends" debian/control && \
	apt-get -y --purge remove freeradius-build-deps && \
	cd / && \
	rm -rf /tmp/freeradius-build \
		/freeradius-build-deps_*.deb /freeradius-build-deps_*.buildinfo /freeradius-build-deps_*.changes

#
#  Trust any workspace path. The job container runs as root but the
#  bind-mounted runner workspace is owned by the runner user; without
#  this, git refuses with "dubious ownership" the moment a Makefile
#  runs `git rev-parse`. System-wide so it applies to every shell.
#
RUN git config --system --add safe.directory '*'
