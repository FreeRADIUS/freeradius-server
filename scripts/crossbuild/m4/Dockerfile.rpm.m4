ARG from=DOCKER_IMAGE
FROM ${from} as build

ifelse(OS_VER, `9', `dnl
#
#  Install yum
#
RUN dnf install -y yum
')dnl

#
#  Install devtools like make and git and the EPEL
#  repository for freetds and hiredis
#
RUN yum update -y
RUN yum install -y rpmdevtools openssl epel-release git procps yum-utils \
	rsync ifelse(OS_VER, `7',, `dnf-plugins-core')

ifelse(OS_VER, `7', `dnl
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
')dnl

ifelse(OS_VER, `8', `dnl
RUN yum config-manager --set-enabled powertools

#
#  Install GCC that has the requisite support for C11 keywords and atomics
#
RUN yum install -y gcc-toolset-9
')dnl

ifelse(OS_VER, `9', `dnl
RUN yum config-manager --set-enabled crb
')dnl

#
#  Documentation build dependecies
#
define(`NODE_VER', ifelse(OS_VER, 7, `16', `20'))dnl

#  - doxygen & JSON.pm
RUN yum install -y doxygen graphviz perl-JSON
#  - antora (npm needed)
RUN curl -sL https://rpm.nodesource.com/setup_`'NODE_VER.x | bash -
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

changequote([{,}])dnl Only add LTB on centos7/rocky8
ifelse(ifelse(OS_VER, 7, yes,   OS_VER, 8, yes,   no), yes, [{dnl
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
}])dnl
changequote(`,')dnl

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
define(`BUILDDEP_EXTRA', ifelse(OS_VER, 7, `--disablerepo="nodesource*"', `-D "_with_rlm_yubikey 1"'))dnl
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e redhat/freeradius.spec ] && yum-builddep BUILDDEP_EXTRA -y redhat/freeradius.spec; \
	done

ifelse(OS_VER, 7,`dnl
#  Yubikey deps for CentOS/RHEL 7
RUN yum install -y ykclient-devel ykclient
')dnl

RUN yum install -y libyubikey-devel

#
#  Which is required by fixture setup utilities
#
RUN yum install -y which

#
#  Explicitly install libnl3-devel which is required for the EAP tests
#
RUN yum install -y libnl3-devel

ifelse(OS_VER, 7,, `dnl
#
#  We test with TLS1.1, but that is disabled by default on some
#  newer systems.
#
RUN update-crypto-policies --set LEGACY
')dnl

#
#  Create the RPM build tree
#
RUN rpmdev-setuptree
