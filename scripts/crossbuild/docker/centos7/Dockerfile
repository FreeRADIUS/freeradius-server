# Auto generated for centos7
# from scripts/crossbuild/m4/Dockerfile.rpm.m4
#
# Rebuild this file with `make crossbuild.centos7.regen`
#
ARG from=centos:7
FROM ${from} as build

#
#  Install devtools like make and git and the EPEL
#  repository for freetds and hiredis
#
RUN yum update -y
RUN yum install -y rpmdevtools openssl epel-release git procps yum-utils \
	rsync 

#
#  Install GCC that has the requisite support for C11 keywords and atomics
#
RUN yum install -y centos-release-scl
RUN yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++
ENV CC=/opt/rh/devtoolset-8/root/usr/bin/gcc

#
#  Remove the CentOS-SCLo repo which is apparently not valid?
#  See: https://bugs.centos.org/view.php?id=14773
#
RUN rm /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo
RUN rm /etc/yum.repos.d/CentOS-SCLo-scl.repo



#
#  Documentation build dependecies
#

#  - doxygen & JSON.pm
RUN yum install -y doxygen graphviz perl-JSON
#  - antora (npm needed)
RUN curl -sL https://rpm.nodesource.com/setup_16.x | bash -
RUN yum install -y nodejs
RUN npm i -g @antora/cli@3.1.7 @antora/site-generator-default@3.1.7
#  - pandoc
RUN curl -o - -L $(curl -s https://api.github.com/repos/jgm/pandoc/releases/latest | grep "browser_download_url.*tar.gz" | cut -d '"' -f 4) | tar xzvf - -C /tmp/
RUN mv /tmp/pandoc-*/bin/* /usr/local/bin
#  - asciidoctor
RUN yum install -y rubygems-devel
RUN gem install asciidoctor

#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Use LTB's openldap packages intead of the distribution version to avoid linking against NSS
#
RUN echo $'[ltb-project]\n\
name=LTB project packages\n\
baseurl=https://ltb-project.org/rpm/$releasever/$basearch\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-LTB-project'\
> /etc/yum.repos.d/ltb-project.repo
RUN rpm --import https://ltb-project.org/lib/RPM-GPG-KEY-LTB-project

#
#  Shallow clone the FreeRADIUS source
#
WORKDIR /usr/local/src/repositories
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}

#
#  Install build dependencies for all branches from v3 onwards
#  Nodesource has issues (no SRPMS in some repos) and is not needed here
#  CentOS/RHEL 7 do not support "-D" for yum-builddep so do that separately below if needed
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e redhat/freeradius.spec ] && yum-builddep --disablerepo="nodesource*" -y redhat/freeradius.spec; \
	done

#  Yubikey deps for CentOS/RHEL 7
RUN yum install -y ykclient-devel ykclient

RUN yum install -y libyubikey-devel

#
#  Which is required by fixture setup utilities
#
RUN yum install -y which

#
#  Explicitly install libnl3-devel which is required for the EAP tests
#
RUN yum install -y libnl3-devel


#
#  Create the RPM build tree
#
RUN rpmdev-setuptree
