ARG from=DOCKER_IMAGE
FROM ${from} AS build

include(`common.dnf.retries.m4')dnl
include(`common.rpm.toolchain.m4')dnl
include(`common.rpm.nr-extras.m4')dnl

#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
WORKDIR /usr/local/src/repositories
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}

#
#  Install build dependencies for all branches from v3 onwards
#  Nodesource has issues (no SRPMS in some repos) and is not needed here
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[4-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e redhat/freeradius.spec ] && dnf builddep -y redhat/freeradius.spec; \
	done

#
#  A few extra packages needed for tests
#
RUN dnf install -y \
    libnl3-devel \
    libyubikey-devel \
    oathtool \
    which

#
#  We test with TLS1.1, but that is disabled by default on some
#  newer systems.
#
RUN update-crypto-policies --set LEGACY

#
#  Create the RPM build tree
#
RUN rpmdev-setuptree
