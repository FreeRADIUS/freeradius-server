#
#  Refresh dnf metadata and install the build toolchain shared by the
#  production, crossbuild, and CI base templates. CRB is enabled because
#  the build-dep closure pulls packages that live there. OS_VER is
#  substituted by the dispatcher (Dockerfile.m4) per Rocky major version.
#
RUN rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-OS_VER

RUN dnf update -y
RUN dnf install -y \
		dnf-plugins-core \
		dnf-utils \
		epel-release \
		git \
		openssl \
		procps \
		rpmdevtools \
		rsync

RUN dnf config-manager --set-enabled crb

ifelse(OS_VER, `9', `dnl
#
#  The system gcc 11 on Rocky 9 predates C23, which FreeRADIUS
#  requires. gcc-toolset-14 supplies a new enough gcc; putting the
#  toolset bin directory first in PATH makes every later build step
#  use the toolset gcc without sourcing the enable script. The annobin
#  plugin is needed so rpmbuild hardening annotations keep working
#  with the toolset compiler.
#
RUN dnf install -y gcc-toolset-14-gcc gcc-toolset-14-gcc-c++ gcc-toolset-14-annobin-plugin-gcc
ENV PATH=/opt/rh/gcc-toolset-14/root/usr/bin:$PATH

')dnl
dnl  EPEL mirror lists can only be snapshotted after the epel-release
dnl  install above puts the repo files in place.
include(`common.dnf.mirrorlist.epel.m4')dnl
include(`common.rpm.libkqueue.m4')dnl
