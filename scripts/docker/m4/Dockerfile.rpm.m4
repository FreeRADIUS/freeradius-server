ARG from=DOCKER_IMAGE
FROM ${from} as build

ifelse(OS_VER, 8, `dnl
RUN rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial
')dnl
ifelse(OS_VER, 9, `dnl
RUN rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
')
#
#  Install build tools
#
RUN yum groupinstall -y "Development Tools"
ifelse(OS_VER, 7,`dnl
RUN yum install -y rpmdevtools
RUN yum install -y openssl
',`
RUN yum install -y rpmdevtools openssl dnf-utils
')

#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
ARG release=v3.2.x

RUN git clone --depth 1 --single-branch --branch ${release} ${source}
WORKDIR freeradius-server

#
#  Other requirements
#
changequote(`{', `}')dnl
ifelse(ifelse(OS_VER, 7, yes, OS_VER, 8, yes, no), yes, {
#  Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo
RUN rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project
})dnl
changequote({`}, {'})dnl

#  Enable EPEL repository for freetds and hiredis
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-OS_VER.noarch.rpm
ifelse(OS_VER, 8, `
#  Enable powertools repo
RUN yum config-manager --enable powertools

#  Enable epel-testing, currently needed for hiredis-devel
RUN yum config-manager --enable epel-testing
')dnl
ifelse(OS_VER, 9, `
#  Enable Code Ready Builder repo (CentOS powertools equivalent)
RUN yum install -y yum-utils
RUN yum config-manager --enable crb
')dnl

#
#  Install build dependencies
#
#  Run twice, it doesn't always get everything with one invocation
#
RUN [ -e redhat/freeradius.spec ] && \
	yum-builddep -y redhat/freeradius.spec && \
	yum-builddep -y redhat/freeradius.spec

#
#  Create RPM build environment
#
ENV BUILDDIR=/root/rpmbuild
RUN rpmdev-setuptree

RUN ./configure
RUN make freeradius-server-$(cat VERSION).tar.bz2
RUN cp freeradius-server-$(cat VERSION).tar.bz2 $BUILDDIR/SOURCES/
RUN cp -r redhat/* $BUILDDIR/SOURCES/
RUN cp -r redhat/freeradius.spec $BUILDDIR/SPECS/
WORKDIR $BUILDDIR

#
#  Build the server
#
ENV QA_RPATHS=0x0003
RUN rpmbuild -bb --define '_release $release' "$BUILDDIR/SPECS/freeradius.spec"

RUN mkdir /root/rpms
RUN mv $BUILDDIR/RPMS/*/*.rpm /root/rpms/

#
#  Clean environment and run the server
#
FROM ${from}
COPY --from=build /root/rpms /tmp/

changequote(`{', `}')dnl
ifelse(ifelse(OS_VER, 7, yes, OS_VER, 8, yes, no), yes, {dnl
# Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo \
    && rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project
})dnl
changequote({`}, {'})dnl

ifelse(OS_VER, 9, `dnl
#  Needed for mysql-libs on Rocky 9
RUN yum install -y yum-utils
RUN yum config-manager --enable crb
')dnl

#  EPEL repository for freetds and hiredis
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-OS_VER.noarch.rpm \
ifelse(OS_VER, 7, `    \', `dnl
    && yum install -y dnf-utils \
    && yum config-manager --enable epel-testing

ARG radiusd_uid=95
ARG radiusd_gid=95

RUN groupadd -g ${radiusd_gid} -r radiusd \
    && useradd -u ${radiusd_uid} -g radiusd -r -M -d /home/radiusd -s /sbin/nologin radiusd \')
    && yum install -y /tmp/*.rpm

COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["radiusd"]
