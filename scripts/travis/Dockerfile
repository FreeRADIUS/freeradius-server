FROM ubuntu:16.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
	apt-get upgrade -y

RUN apt-get install -y \
	software-properties-common \
	wget \
	curl


#
#  Set up extra repositories
#
#  GCC and clang
RUN add-apt-repository -y ppa:ubuntu-toolchain-r/test
RUN add-apt-repository -y "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-8 main"

#  cmake (script below used instead)
# RUN add-apt-repository -y ppa:rjvbertin/misc

#  Redis and PostgreSQL
RUN add-apt-repository ppa:chris-lea/redis-server
RUN add-apt-repository "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -sc)-pgdg main"


#
#  Install repo keys
#
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | \
	apt-key add -

RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | \
	apt-key add -


#
#  Update with repos added above
#
RUN apt-get update && \
	apt-get upgrade -y


#
#  Install everything needed
#
RUN apt-get install -y \
	autoconf \
	build-essential \
	clang-8 \
	debhelper \
	devscripts \
	dh-make \
	doxygen \
	fakeroot \
	firebird-dev \
	freetds-dev \
	gcc-7 \
	gccgo-7 \
	gdb \
	graphviz \
	ldap-utils \
	libcollectdclient-dev \
	libcap-dev \
	libcurl4-openssl-dev \
	libgdbm-dev \
	libhiredis-dev \
	libidn11-dev \
	libiodbc2-dev \
	libiodbc2 \
	libjson0 \
	libjson0-dev \
	libkrb5-dev \
	libldap2-dev \
	libluajit-5.1-dev \
	libmemcached-dev \
	libmysqlclient-dev \
	libnl-genl-3-dev \
	libpam0g-dev \
	libpcap-dev \
	libpcre3-dev \
	libperl-dev \
	libpq-dev \
	libpython-all-dev \
	libreadline-dev \
	libsnmp-dev \
	libssl-dev \
	libtalloc-dev \
	libtalloc2-dbg \
	libunbound-dev \
	libwbclient-dev \
	libykclient-dev \
	libyubikey-dev \
	lintian \
	llvm-8 \
	luajit \
	lynx \
	mysql-server \
	pbuilder \
	postgresql-10 \
	postgresql-client-10 \
	python-dev \
	quilt \
	slapd \
	ruby \
	git \
	redis-server \
	jq


#
#  Install cmake
#
RUN curl -f -o cmake.sh https://cmake.org/files/v3.8/cmake-3.8.2-Linux-x86_64.sh 
RUN [ "$(cat cmake.sh | openssl sha256 | sed 's/^.* //')" = "bb26b1871f9e5c2fb73476186cc94d03b674608f704b48b94d617340b87b4d73" ]
RUN sh cmake.sh --skip-license --prefix=/usr/local


#
#  Install libkqueue
#
WORKDIR /usr/local/src/repositories

RUN git clone --branch master --depth=1 https://github.com/mheily/libkqueue.git

### Get the latest release of libkqueue 
# RUN curl -sL https://github.com/mheily/libkqueue/archive/09f9ae5560974f132ee9e8313e2b6c82c7e74f69.tar.gz > libkqueue.tgz
# RUN curl -sL $(curl -s https://api.github.com/repos/mheily/libkqueue/releases/latest | jq -r .tarball_url) > libkqueue.tgz 
### Figure out the directory structure. 
# RUN tar zxf libkqueue.tgz && mv $(tar ztf libkqueue.tgz | head -1) libkqueue

WORKDIR /usr/local/src/repositories/libkqueue

RUN cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib ./ && \
	make && \
	cpack -G DEB && \
	dpkg -i --force-all ./libkqueue*.deb

WORKDIR /usr/local/src/repositories
