FROM ubuntu:24.04

ARG llvm_ver=18
ARG gcc_ver=14
ARG openssl_ver=3.0.2

ENV DEBIAN_FRONTEND=noninteractive

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
	libasan6 \
	lsb-release \
	python3-pip \
	quilt \
	ruby-dev \
	software-properties-common \
	wget

#
#  Set up Ubuntu toolchain repo
#
RUN add-apt-repository -y ppa:ubuntu-toolchain-r/test

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
RUN mkdir -p /etc/apt/keyrings && \
	curl -sS -o /etc/apt/keyrings/openresty.asc \
	https://openresty.org/package/pubkey.gpg

RUN RELEASE=$(lsb_release -cs) && \
	echo "deb [signed-by=/etc/apt/keyrings/openresty.asc] http://openresty.org/package/ubuntu $(lsb_release -sc) main" \
		> /etc/apt/sources.list.d/openresty.list && \
	apt-get update

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
	mariadb-client \
	openresty \
	postgresql-client \
	redis-server \
	redis-tools \
	slapd \
	winbind
#	samba \


#
#  Additional improvements
#  - install eapol_test
#  - install openssl 3.0 (needs CI update to enable/disable)
#
