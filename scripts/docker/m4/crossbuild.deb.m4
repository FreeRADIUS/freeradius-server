ARG from=DOCKER_IMAGE
FROM ${from} AS build

SHELL ["/usr/bin/nice", "-n", "5", "/usr/bin/ionice", "-c", "3", "/bin/sh", "-x", "-c"]

ARG APT_OPTS="-y --option=Dpkg::options::=--force-unsafe-io --no-install-recommends"

ARG DEBIAN_FRONTEND=noninteractive


#
#  Install add-apt-repository (may be needed for clang) and
#  package development utilities
#
RUN apt-get update && \
    apt-get install $APT_OPTS \
        devscripts \
        equivs \
        git \
        gnupg2 \
        lsb-release \
        procps \
        quilt \
        rsync \
        wget && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*


#
#  Set up NetworkRADIUS extras repository
#
RUN install -d -o root -g root -m 0755 /etc/apt/keyrings && \
    wget -O /etc/apt/keyrings/packages.networkradius.com.asc "https://packages.networkradius.com/pgp/packages%40networkradius.com" && \
    echo "deb [signed-by=/etc/apt/keyrings/packages.networkradius.com.asc] http://packages.networkradius.com/extras/OS_NAME/OS_CODENAME OS_CODENAME main" > /etc/apt/sources.list.d/networkradius-extras.list && \
    apt-get update

dnl
dnl  Work out what clang packages we want to install
dnl
define(`CLANG_PKGS', `llvm clang lldb')dnl
ifelse(D_NAME, `debian10', `dnl
define(`CLANG_VER', `11')dnl
define(`CLANG_PKGS', `llvm-CLANG_VER clang-CLANG_VER lldb-CLANG_VER')dnl

#
#  Add repository for clang
#
RUN add-apt-repository -y "deb http://apt.llvm.org/OS_CODENAME/ llvm-toolchain-OS_CODENAME-CLANG_VER main" && \
    apt-key adv --fetch-keys http://apt.llvm.org/llvm-snapshot.gpg.key
')dnl

#
#  Install compilers
#
RUN apt-get install $APT_OPTS \
        g++ \
        CLANG_PKGS

ifelse(D_NAME, `debian10', `dnl
#
#  Set defaults
#
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-CLANG_VER 60 && \
    update-alternatives --config clang

RUN update-alternatives --install /usr/bin/lldb lldb /usr/bin/lldb-CLANG_VER 60 && \
    update-alternatives --config lldb
')

ifelse(D_NAME, `debiansid', `dnl
#
#  Debian sid has OpenSSL legacy provider in an optional package
#
RUN apt-get install $APT_OPTS openssl-provider-legacy
')

#
#  Install some extra packages
#
RUN apt-get install $APT_OPTS \
dnl
dnl for eapol_test:
        libnl-3-dev \
        libnl-genl-3-dev \
dnl
dnl for debugging:
        gdb \
        less \
        lldb \
        vim \
dnl
dnl for tests:
        oathtool


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
#  Install build dependencies for all branches from v4 onwards
#  Debian sid fails if debian/control doesn't exist due to an issue
#  in one of the included make files, so we create a blank file.
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[4-9]*\.[0-9x]*\.x|master|${branch})$" | sort -u); \
    do \
        git checkout $i; \
        if [ -e ./debian/control.in ] ; then \
	    touch -t 202001010000 debian/control; \
            debian/rules debian/control ; \
        fi ; \
        mk-build-deps -irt"apt-get -o Debug::pkgProblemResolver=yes $APT_OPTS" debian/control ; \
        apt-get -y remove libiodbc2-dev ; \
    done
