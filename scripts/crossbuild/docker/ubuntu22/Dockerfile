# Auto generated for ubuntu22
# from scripts/crossbuild/m4/Dockerfile.deb.m4
#
# Rebuild this file with `make crossbuild.ubuntu22.regen`
#
ARG from=ubuntu:22.04
FROM ${from} as build

ARG DEBIAN_FRONTEND=noninteractive

#
#  Install add-apt-repository
#
RUN apt-get update && \
    apt-get install -y software-properties-common gnupg2 procps && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*


RUN apt-get update && \
#  Development utilities
    apt-get install -y devscripts equivs git quilt rsync && \
#  Compilers
    apt-get install -y g++ llvm clang lldb && \
#  eapol_test dependencies
    apt-get install -y libnl-3-dev libnl-genl-3-dev

#
#  Documentation build dependecies
#

#  - doxygen & JSON.pm
RUN apt-get install -y doxygen graphviz libjson-perl
#  - antora (npm needed)
RUN curl -sL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get install -y nodejs
RUN npm i -g @antora/cli@3.1.7 @antora/site-generator-default@3.1.7
#  - pandoc
WORKDIR /tmp
RUN curl -OL $(curl -s https://api.github.com/repos/jgm/pandoc/releases/latest | grep "browser_download_url.*deb" | cut -d '"' -f 4)
RUN apt-get install -y ./pandoc-*.deb
#  - asciidoctor
RUN apt-get install -y ruby-dev
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
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		if [ -e ./debian/control.in ] ; then \
			debian/rules debian/control ; \
		fi ; \
		echo 'y' | \
		mk-build-deps -irt'apt-get -yV' debian/control ; \
	done
