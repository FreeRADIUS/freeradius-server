ARG from=DOCKER_IMAGE
FROM ${from} AS build

#
#  Install devtools like make and git and the EPEL
#  repository for freetds and hiredis
#
RUN dnf update -y
RUN dnf install -y rpmdevtools openssl epel-release git procps dnf-utils \
	rsync dnf-plugins-core

RUN dnf config-manager --set-enabled crb

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
RUN curl -o - -L $(curl -s https://api.github.com/repos/jgm/pandoc/releases/latest | grep "browser_download_url.*tar.gz" | cut -d '"' -f 4 | head -1) | tar xzvf - -C /tmp/
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
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[4-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e redhat/freeradius.spec ] && dnf builddep -y redhat/freeradius.spec; \
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
