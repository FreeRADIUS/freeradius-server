FROM centos:8

# Seems to work around https://bugs.centos.org/view.php?id=16655
RUN rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

RUN yum groupinstall -y "Development Tools"
RUN yum install -y rpmdevtools openssl dnf-utils

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

RUN git clone --depth 1 --single-branch --branch ${release} ${source}
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
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
# Currently needed for hiredis:
RUN yum config-manager --enable epel-testing
# For json-c-devel and libpcap-devel ("PowerTools"?!):
RUN yum config-manager --enable PowerTools

#
#  Install build dependencies
#
RUN [ -e redhat/freeradius.spec ] && yum-builddep -y redhat/freeradius.spec

