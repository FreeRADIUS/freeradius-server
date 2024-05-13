ARG from=DOCKER_IMAGE
FROM ${from} as build

#
#  Install devtools like make and git and the EPEL
#  repository for freetds and hiredis
#
RUN dnf update -y
RUN dnf install -y rpmdevtools openssl epel-release git procps dnf-utils \
	rsync`'ifelse(OS_VER, `7',, ` dnf-plugins-core')

ifelse(OS_VER, `7', `dnl
#
#  Install GCC that has the requisite support for C11 keywords and atomics
#
RUN dnf install -y centos-release-scl
RUN dnf install -y devtoolset-8-gcc devtoolset-8-gcc-c++
ENV CC=/opt/rh/devtoolset-8/root/usr/bin/gcc

#
#  Remove the CentOS-SCLo repo which is apparently not valid?
#  See: https://bugs.centos.org/view.php?id=14773
#
RUN rm /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo
RUN rm /etc/yum.repos.d/CentOS-SCLo-scl.repo
')dnl

ifelse(OS_VER, `8', `dnl
RUN dnf config-manager --set-enabled powertools

#
#  Install GCC that has the requisite support for C11 keywords and atomics
#
RUN dnf install -y gcc-toolset-9
')dnl

ifelse(OS_VER, `9', `dnl
RUN dnf config-manager --set-enabled crb
')dnl

#
#  Documentation build dependencies
#
define(`NODE_VER', `20')dnl
define(`ANTORA_VER', `3.1.7')dnl

#  - doxygen & JSON.pm
RUN dnf install -y doxygen graphviz perl-JSON
#  - antora (npm needed)
RUN curl -sL https://rpm.nodesource.com/setup_`'NODE_VER.x | bash -
RUN dnf install -y nodejs
RUN npm i -g @antora/cli@ANTORA_VER @antora/site-generator-default@ANTORA_VER
#  - pandoc
RUN curl -o - -L $(curl -s https://api.github.com/repos/jgm/pandoc/releases/latest | grep "browser_download_url.*tar.gz" | cut -d '"' -f 4) | tar xzvf - -C /tmp/
RUN mv /tmp/pandoc-*/bin/* /usr/local/bin
#  - asciidoctor
RUN dnf install -y rubygems-devel
RUN gem install asciidoctor

#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

changequote([{,}])dnl
#
#  Set up NetworkRADIUS extras repository for latest libkqueue
#
RUN echo $'[networkradius-extras]\n\
name=NetworkRADIUS-extras-$releasever\n\
baseurl=http://packages.networkradius.com/extras/OS_NAME/$releasever/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=https://packages.networkradius.com/pgp/packages@networkradius.com'\
> /etc/yum.repos.d/networkradius-extras.repo
RUN rpm --import https://packages.networkradius.com/pgp/packages@networkradius.com
ifelse(ifelse(OS_VER, 7, yes,   OS_VER, 8, yes,   no), yes, [{dnl Only add LTB on centos7/rocky8

#
#  Use LTB's openldap packages instead of the distribution version to avoid linking against NSS
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
#
define(`EXTRA_DISABLE', ifelse(OS_VER, 7, `--disablerepo="nodesource*"', `'))dnl
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[4-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e redhat/freeradius.spec ] && dnf builddep EXTRA_DISABLE -y redhat/freeradius.spec; \
	done

#
#  A few extra packages needed for tests
#
RUN dnf install -y \
    libnl3-devel \
    libyubikey-devel \
    oathtool \
    which

#
#  We test with TLS1.1, but that is disabled by default on some
#  newer systems.
#
RUN update-crypto-policies --set LEGACY

#
#  Create the RPM build tree
#
RUN rpmdev-setuptree
