ARG from=DOCKER_IMAGE
FROM ${from} AS build

include(`common.dnf.retries.m4')dnl
include(`common.rpm.toolchain.m4')dnl
include(`common.rpm.nr-extras.m4')dnl

#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories/freeradius-server
WORKDIR /usr/local/src/repositories/freeradius-server/

#
#  Copy the FreeRADIUS directory in
#
COPY . .

#
#  Clean up tree - we want to build from the latest commit, not from
#  any cruft left around on the local system
#
RUN git clean -fdxx \
 && git reset --hard HEAD

#
#  Install build dependencies
#
#  Run twice, it doesn't always get everything with one invocation
RUN [ -e redhat/freeradius.spec ] && \
	dnf builddep -y redhat/freeradius.spec && \
	dnf builddep -y redhat/freeradius.spec

#
#  Create RPM build environment
#
ENV BUILDDIR=/root/rpmbuild
RUN rpmdev-setuptree

RUN ./configure
RUN make pkg_version > /VERSION
RUN cat /VERSION
RUN make freeradius-server-$(cat /VERSION).tar.bz2
RUN cp freeradius-server-$(cat /VERSION).tar.bz2 $BUILDDIR/SOURCES/
RUN cp -r redhat/* $BUILDDIR/SOURCES/
RUN make dist-check-rpm
RUN cp -r redhat/freeradius.spec $BUILDDIR/SPECS/
WORKDIR $BUILDDIR

#
#  Build the server
#
ENV QA_RPATHS=0x0003
RUN rpmbuild -bb --define "_release $(cat /VERSION)" "$BUILDDIR/SPECS/freeradius.spec"

RUN mkdir /root/rpms
RUN mv $BUILDDIR/RPMS/*/*.rpm /root/rpms/

#
#  Clean environment and run the server
#
FROM ${from}

include(`common.dnf.retries.m4')dnl

COPY --from=build /root/rpms /tmp/

#
#  libkqueue isn't in the Rocky archives; the build stage built it from
#  source (via common.rpm.libkqueue.m4). Ferry the runtime rpm across so
#  freeradius's `Requires: libkqueue` resolves at install time.
#
COPY --from=build /opt/libkqueue-rpms/libkqueue-[0-9]*.rpm /tmp/

include(`common.rpm.nr-extras.m4')dnl

#
#  Other requirements
#

#  Needed for mysql-libs
RUN dnf install -y dnf-utils
RUN dnf config-manager --enable crb

#  EPEL repository for freetds and hiredis
RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-OS_VER.noarch.rpm \
    && dnf install -y dnf-utils \
    && dnf config-manager --enable epel-testing

ARG radiusd_uid=95
ARG radiusd_gid=95

RUN groupadd -g ${radiusd_gid} -r radiusd \
    && useradd -u ${radiusd_uid} -g radiusd -r -M -d /home/radiusd -s /sbin/nologin radiusd \
    && dnf install -y /tmp/*.rpm

WORKDIR /
COPY scripts/docker/etc/docker-entrypoint.sh.PKG_TYPE docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["radiusd"]
