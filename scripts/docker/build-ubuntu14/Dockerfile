FROM ubuntu:14.04
RUN apt-get update && apt-get install -y devscripts equivs git quilt

#
#  Install GCC-4.9 as it has the requisite support for C11 keywords and atomics
#
RUN apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update
RUN apt-get install -y g++-4.9 llvm-3.9 clang-3.9 lldb-3.9

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 50 --slave /usr/bin/g++ g++ /usr/bin/g++-4.9 && update-alternatives --config gcc
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.9 60 && update-alternatives --config clang
RUN update-alternatives --install /usr/bin/lldb lldb /usr/bin/lldb-3.9 60 && update-alternatives --config lldb

#
#  Install eapol_test dependencies
#
RUN apt-get install libnl-3-dev libnl-genl-3-dev

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
# Fixme: Change to the main repo when they merge this branch
RUN git clone --branch patch-3 --depth=1 https://github.com/arr2036/libkqueue.git
WORKDIR libkqueue
RUN cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib ./ && \
    make && \
    cpack -G DEB
RUN apt-get install -y ./*.deb
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}
WORKDIR freeradius-server

#
#  Install build dependencies for all branches
#
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^v[0-9]*\.[0-9x]*\.x$");\
	do \
		git checkout $i; \
		if [ -e ./debian/control.in ] ; then debian/rules debian/control ; fi ; echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control ; \
	done

### For some reason this dep was not installed

#
#  This is necessary for the jenkins server to talk to the docker instance
#
#RUN echo deb http://archive.ubuntu.com/ubuntu trusty-backports main restricted universe multiverse >>  /etc/apt/sources.list
RUN apt-add-repository ppa:openjdk-r/ppa
RUN apt-get update && apt-get install -y openjdk-8-jre-headless
RUN apt-get install -y openssh-server
RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers
RUN mkdir /var/run/sshd
# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
