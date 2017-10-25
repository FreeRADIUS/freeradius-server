FROM debian:stretch
RUN apt-get update && apt-get install -y devscripts equivs git quilt

#
#  Stretch uses gcc4.9 by default, so we don't need to install any additional compilers to get C11 functionality
#

#
#  Install eapol_test dependencies
#
RUN apt-get install -y libnl-3-dev libnl-genl-3-dev

#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src

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

#
#  Shallow clone the FreeRADIUS source
#
WORKDIR /usr/local/src/repositories
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}
WORKDIR freeradius-server

#
#  Install build dependencies for all branches
#
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^v[0-9]*\.[0-9x]*\.x$");\
	do \
		git checkout $i; \
		[ -e ./debian/control.in ] && debian/rules debian/control && echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control; \
	done

#
#  This is necessary for the jenkins server to talk to the docker instance
#
RUN echo deb http://ftp.debian.org/debian stretch-backports main >> /etc/apt/sources.list
RUN apt-get update && apt-get -t stretch-backports install -y openjdk-8-jre-headless 
RUN apt-get install -y openssh-server sudo 

RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers
RUN mkdir /var/run/sshd

# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
