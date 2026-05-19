ARG from=DOCKER_IMAGE
FROM ${from}

ENV DEBIAN_FRONTEND=noninteractive

include(`common.apt.retries.m4')dnl
include(`common.deb.toolchain.m4')dnl

#
#  Extras the CI base needs on top of the common toolchain. xz-utils
#  feeds the tmate debug step; file is occasionally invoked from
#  debian/rules.
#
RUN apt-get install -y --no-install-recommends \
		file \
		xz-utils

include(`common.deb.nr-extras.m4')dnl

#
#  Pre-install the build-dep closure derived from debian/control. The
#  source-tree debian/ subtree is baked in at image-build time; ci-deb.yml
#  still runs mk-build-deps per job as a top-up so newly added deps are
#  picked up without an image rebuild.
#
COPY debian/ /tmp/freeradius-debian/
COPY scripts/ci/extra-packages.debian.control /tmp/freeradius-debian-extras.control
RUN cd /tmp/freeradius-debian && \
	touch -t 202001010000 control && \
	./rules control && \
	mk-build-deps -irt"apt-get -y --no-install-recommends" control && \
	cd / && \
	mk-build-deps -irt"apt-get -y --no-install-recommends" /tmp/freeradius-debian-extras.control && \
	rm -rf /tmp/freeradius-debian /tmp/freeradius-debian-extras.control \
		/freeradius-build-deps_*.deb /freeradius-build-deps_*.buildinfo /freeradius-build-deps_*.changes

#
#  Trust any workspace path. The job container runs as root but the
#  bind-mounted runner workspace is owned by the runner user; without
#  this, git refuses with "dubious ownership" the moment a Makefile
#  runs `git rev-parse`. System-wide so it applies to every shell.
#
RUN git config --system --add safe.directory '*'
