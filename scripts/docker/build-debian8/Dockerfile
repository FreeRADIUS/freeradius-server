FROM debian:jessie
RUN apt-get update && apt-get install -y devscripts equivs git quilt

#
#  Install GCC-4.9 as it has the requisite support for C11 keywords and atomics
#
RUN apt-get install -y g++-4.9
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 50 --slave /usr/bin/g++ g++ /usr/bin/g++-4.9 && update-alternatives --config gcc

#
#  Install eapol_test dependencies
#
RUN apt-get install libnl-3-dev libnl-genl-3-dev

#
#  Setup a src dir in /usr/local
#
WORKDIR /usr/local/src/repositories
RUN git clone --depth=1 https://github.com/FreeRADIUS/freeradius-server.git
WORKDIR freeradius-server

# Install build dependencies for all branches
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^v[0-9]*\.[0-9x]*\.x$");\
	do \
		git checkout $i; \
		[ -e ./debian/control.in ] && debian/rules debian/control && echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control; \
	done

### For some reason this dep was not installed
# RUN apt-get install -y libiodbc2-dev

#
#  This is necessary for the jenkins server to talk to the docker instance
#
RUN echo deb http://ftp.debian.org/debian jessie-backports main >> /etc/apt/sources.list
RUN apt-get update && apt-get -t jessie-backports install -y openjdk-8-jre-headless 
RUN apt-get install -y openssh-server sudo 

RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers

RUN mkdir /var/run/sshd
# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
