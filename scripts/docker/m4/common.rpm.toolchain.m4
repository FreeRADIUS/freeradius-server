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

dnl  EPEL mirror lists can only be snapshotted after the epel-release
dnl  install above puts the repo files in place.
include(`common.dnf.mirrorlist.epel.m4')dnl
include(`common.rpm.libkqueue.m4')dnl
