FROM centos:6
RUN yum groupinstall -y "Development Tools"
RUN yum install -y rpmdevtools
RUN yum install -y openssl yum-utils

#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
ARG release=v3.0.x

RUN git clone --depth 1 --branch ${release} ${source}
WORKDIR freeradius-server
#
#  Other requirements
#

# Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo
RUN rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project

# EPEL repository for freetds and hiredis
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm

#
#  Install build dependencies
#
# RUN [ -e redhat/freeradius.spec ] && yum-builddep -y redhat/freeradius.spec

