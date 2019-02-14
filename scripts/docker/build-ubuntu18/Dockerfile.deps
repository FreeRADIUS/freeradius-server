FROM ubuntu:18.04

ARG gccver=4.9
ARG clangver=5.0
ARG osname=bionic

ARG DEBIAN_FRONTEND=noninteractive

#
#  Install add-apt-repository
#
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*

RUN apt-get update && \
#  Development utilities
    apt-get install -y devscripts equivs git quilt && \
#  Compilers
    apt-get install -y g++ llvm clang lldb && \
#  eapol_test dependencies
    apt-get install -y libnl-3-dev libnl-genl-3-dev


#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Get a modern version of cmake.  We need 3.8.2 or later to build libkqueue rpms
#
RUN curl -f -o cmake.sh https://cmake.org/files/v3.8/cmake-3.8.2-Linux-x86_64.sh
RUN [ "$(cat cmake.sh | openssl sha256 | sed 's/^.* //')" = "bb26b1871f9e5c2fb73476186cc94d03b674608f704b48b94d617340b87b4d73" ]
RUN sh cmake.sh --skip-license --prefix=/usr/local

#
#  Grab libkqueue and build
#
WORKDIR /usr/local/src/repositories
RUN git clone --branch master --depth=1 https://github.com/mheily/libkqueue.git

WORKDIR libkqueue
RUN cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib ./ && \
    make && \
    cpack -G DEB && \
    dpkg -i --force-all ./libkqueue*.deb


#
#  Shallow clone the FreeRADIUS source
#
WORKDIR /usr/local/src/repositories
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}

#
#  Install build dependencies for all branches from v3 onwards
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		if [ -e ./debian/control.in ] ; then debian/rules debian/control ; fi ; echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control ; \
	done
