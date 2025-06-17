# Auto generated for rocky10
# from scripts/crossbuild/m4/Dockerfile.rpm.m4
#
# Rebuild this file with `make crossbuild.rocky10.regen`
#
ARG from=rockylinux/rockylinux:10
FROM ${from} as build

#
#  Install yum
#
RUN dnf install -y yum

#
#  Install devtools like make and git and the EPEL
#  repository for freetds and hiredis
#
RUN yum update -y
RUN yum install -y rpmdevtools openssl epel-release git procps yum-utils \
	rsync dnf-plugins-core



RUN yum config-manager --set-enabled crb

#
#  Documentation build dependecies
#

#  - doxygen & JSON.pm
RUN yum install -y doxygen graphviz perl-JSON
#  - antora (npm needed)
RUN curl -sL https://rpm.nodesource.com/setup_20.x | bash -
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
		[ -e redhat/freeradius.spec ] && yum-builddep -D "_with_rlm_yubikey 1" -y redhat/freeradius.spec; \
	done


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
#  We test with TLS1.1, but that is disabled by default on some
#  newer systems.
#
RUN update-crypto-policies --set LEGACY

#
#  Create the RPM build tree
#
RUN rpmdev-setuptree
