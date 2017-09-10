FROM ubuntu:14.04
RUN apt-get update && apt-get install -y devscripts equivs git quilt
RUN apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update
RUN apt-get install -y g++-4.9 llvm-3.9 clang-3.9

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 50 --slave /usr/bin/g++ g++ /usr/bin/g++-4.9 && update-alternatives --config gcc
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.9 60 && update-alternatives --config clang

#
#  Shallow clone the FreeRADIUS source
#
RUN mkdir -p /usr/local/src/repositories
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
