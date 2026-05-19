FROM ubuntu:24.04

ARG llvm_ver=18
ARG gcc_ver=14
ARG openssl_ver=3.0.2

ENV DEBIAN_FRONTEND=noninteractive

#
#  Add country-based mirrors for the Ubuntu base archive so apt tries
#  nearby mirrors before falling back to the primary.  Run before the
#  first apt-get update so every subsequent install benefits.
#
COPY scripts/ci/ubuntu-mirrors-setup.sh /tmp/ubuntu-mirrors-setup.sh
RUN bash /tmp/ubuntu-mirrors-setup.sh

#
#  Refresh APT lists and ensure up-to-date
#
RUN apt-get update && \
	apt-get dist-upgrade -y

#
#  Install packages needed by the build
#
RUN apt-get install -y --no-install-recommends \
	apt-transport-https \
	build-essential \
	ca-certificates \
	curl \
	devscripts \
	equivs \
	gawk \
	git \
	git-lfs \
	gnupg \
	jq \
	libasan6 \
	lsb-release \
	openssh-client \
	python3-pip \
	quilt \
	rsync \
	ruby-dev \
	software-properties-common \
	wget

#
#  Ubuntu toolchain PPA (ppa:ubuntu-toolchain-r/test) is intentionally omitted.
#  gcc-14 and gcc-13 are both in Ubuntu 24.04 (Noble) universe, so the PPA adds
#  nothing for those versions.  gcc-15 is only in Ubuntu 25.04 (plucky) and has
#  not been backported; no public mirror of this PPA exists.  If gcc-15 support
#  is needed, bump the base image to 25.04 or build GCC from source.
#
#  Uncomment if a future gcc_ver requires a version not yet in Noble:
#RUN add-apt-repository -y ppa:ubuntu-toolchain-r/test

#
#  Set up LLVM apt repo (authoritative source for Clang/LLVM releases)
#
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
		| gpg --dearmor > /usr/share/keyrings/llvm.gpg && \
	RELEASE=$(lsb_release -cs) && \
	echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${RELEASE}/ llvm-toolchain-${RELEASE}-${llvm_ver} main" \
		> /etc/apt/sources.list.d/llvm.list

#
#  Set up Network RADIUS repo
#
RUN mkdir -p /etc/apt/keyrings && \
	curl -sS -o /etc/apt/keyrings/networkradius.asc \
	https://packages.networkradius.com/pgp/packages%40networkradius.com

RUN DIST=$(lsb_release -is | tr '[:upper:]' '[:lower:]') && \
	RELEASE=$(lsb_release -cs) && \
	echo "deb [signed-by=/etc/apt/keyrings/networkradius.asc] http://packages.networkradius.com/extras/${DIST}/${RELEASE} ${RELEASE} main" \
		> /etc/apt/sources.list.d/networkradius-extras.list

RUN apt-get update

#
#  Install some basics
#
#  sudo is to maintain compatibility with GitHub hosted runners
#
RUN apt-get install -y --no-install-recommends \
	git \
	git-lfs \
	sudo

#
#  Install FreeRADIUS build-dep packages
#  After NR repo so that we pick up newer libkqueue packages.
#
COPY freeradius-build-deps.deb /tmp/freeradius-build-deps.deb
COPY freeradius-build-deps-extra.deb /tmp/freeradius-build-deps-extra.deb
RUN apt-get install -y --no-install-recommends /tmp/freeradius-build-deps.deb && \
	apt-get --purge -y remove freeradius-build-deps && \
	apt-get install -y --no-install-recommends /tmp/freeradius-build-deps-extra.deb && \
	apt-get --purge -y remove freeradius-build-deps

RUN PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install tacacs_plus

#
#  Install Clang and GCC
#
RUN apt-get install -y --no-install-recommends \
	clang-${llvm_ver} \
	llvm-${llvm_ver} \
	gcc-${gcc_ver} \
	gdb \
	lldb

#
#  Install Cassandra database
#
#./scripts/ci/cassandra-install.sh


#
#  Install OpenSSL
#
#RUN wget https://www.openssl.org/source/openssl-${openssl_ver}.tar.gz && \
#	tar xzf openssl-${openssl_ver}.tar.gz && \
#	cd openssl-${openssl_ver} && \
#	./Configure --prefix=/opt/openssl --openssldir=. --debug && \
#	make -j `nproc` && \
#	make install_sw


#
#  Download to APT cache but do not install
#
RUN apt-get install -yd --no-install-recommends \
	heimdal-dev \
	libpcre3-dev

#
#  Extra installs for the CI testing stage
#
RUN apt-get update

RUN echo "samba-common samba-common/workgroup string WORKGROUP" | debconf-set-selections && \
	echo "samba-common samba-common/dhcp boolean false" | debconf-set-selections && \
	echo "samba-common samba-common/do_debconf boolean true" | debconf-set-selections

RUN apt-get install -y --no-install-recommends \
	389-ds \
	apparmor-utils \
	dovecot-imapd \
	exim4 \
	ipcalc \
	iproute2 \
	iputils-ping \
	krb5-user \
	ldap-utils \
	libnginx-mod-http-lua \
	lua-cjson \
	mariadb-client \
	nginx \
	postgresql-client \
	redis-server \
	redis-tools \
	slapd \
	winbind
#	samba \


#
#  Trust any workspace path. The job container runs as root but the
#  bind-mounted runner workspace is owned by the runner user; without
#  this, git refuses with "dubious ownership" the moment a Makefile
#  runs `git rev-parse`. system-level so it applies to every shell.
#
RUN git config --system --add safe.directory '*'

#
#  Additional improvements
#  - install eapol_test
#  - install openssl 3.0 (needs CI update to enable/disable)
#
