# Auto generated for centos7
# from scripts/docker/m4/Dockerfile.rpm.m4
#
# Rebuild this file with `make docker.centos7.regen`
#
ARG from=centos:7
FROM ${from} as build

#
#  CentOS 7 is now EOL, so we need to fix up the repo source
#
RUN sed -i "s/^mirrorlist/#mirrorlist/g" /etc/yum.repos.d/CentOS-*
RUN sed -i "s|#\s*baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*



#
#  Install build tools
#
RUN yum groupinstall -y "Development Tools"
RUN yum install -y rpmdevtools
RUN yum install -y openssl


#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories/freeradius-server
WORKDIR /usr/local/src/repositories/freeradius-server/

#
#  Copy the FreeRADIUS directory in
#
COPY . .

#
#  Clean up tree - we want to build from the latest commit, not from
#  any cruft left around on the local system
#
RUN git clean -fdxx \
 && git reset --hard HEAD

ARG release
RUN [ -z "$release" ] || git checkout ${release} ; \
    git status ; \
    git log -1 --oneline

#
#  Other requirements
#

#  Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo
RUN rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project

#  Enable EPEL repository for freetds and hiredis
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

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
RUN cp VERSION /VERSION
RUN make freeradius-server-$(cat /VERSION).tar.bz2
RUN cp freeradius-server-$(cat /VERSION).tar.bz2 $BUILDDIR/SOURCES/
RUN cp -r redhat/* $BUILDDIR/SOURCES/
RUN sed -i "s/^Version:.*/Version: $(cat /VERSION)/" redhat/freeradius.spec
RUN cp -r redhat/freeradius.spec $BUILDDIR/SPECS/
WORKDIR $BUILDDIR

#
#  Build the server
#
ENV QA_RPATHS=0x0003
RUN rpmbuild -bb --define "_release $(cat /VERSION)" "$BUILDDIR/SPECS/freeradius.spec"

RUN mkdir /root/rpms
RUN mv $BUILDDIR/RPMS/*/*.rpm /root/rpms/

#
#  Clean environment and run the server
#
FROM ${from}

COPY --from=build /root/rpms /tmp/

#
#  CentOS 7 is now EOL, so we need to fix up the repo source
#
RUN sed -i "s/^mirrorlist/#mirrorlist/g" /etc/yum.repos.d/CentOS-*
RUN sed -i "s|#\s*baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*


# Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo \
    && rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project


#  EPEL repository for freetds and hiredis
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
    \
    && yum install -y /tmp/*.rpm

WORKDIR /
COPY scripts/docker//etc/docker-entrypoint.sh.rpm docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["radiusd"]
