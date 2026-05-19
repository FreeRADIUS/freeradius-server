ARG from=DOCKER_IMAGE
FROM ${from}

include(`common.dnf.retries.m4')dnl
include(`common.rpm.toolchain.m4')dnl

#
#  Extras the CI base needs on top of the common toolchain. libnl3-devel
#  and which feed the eapol_test build; xz feeds the tmate debug step;
#  gcc / make / perl / rpm-build are pulled by dnf builddep anyway but
#  installing them eagerly keeps the layer cache stable when freeradius.spec
#  changes.
#
RUN dnf install -y \
		gcc \
		libnl3-devel \
		make \
		perl \
		rpm-build \
		which \
		xz

include(`common.rpm.nr-extras.m4')dnl

#
#  Pre-install the build-dep closure for the FreeRADIUS spec. The spec
#  is baked in at image-build time; ci-rpm.yml still runs dnf builddep
#  per job as a top-up so newly added deps are picked up without an
#  image rebuild. Run twice; occasionally dnf misses something first time.
#
COPY redhat/freeradius.spec /tmp/freeradius.spec
RUN dnf builddep -y /tmp/freeradius.spec && \
	dnf builddep -y /tmp/freeradius.spec && \
	rm /tmp/freeradius.spec

#
#  Trust any workspace path. The job container runs as root but the
#  bind-mounted runner workspace is owned by the runner user; without
#  this, git refuses with "dubious ownership" the moment a Makefile
#  runs `git rev-parse`. System-wide so it applies to every shell.
#
RUN git config --system --add safe.directory '*'
