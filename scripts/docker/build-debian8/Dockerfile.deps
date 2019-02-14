FROM debian:jessie

ARG gccver=4.9
ARG clangver=5.0
ARG osname=jessie

ARG DEBIAN_FRONTEND=noninteractive

#
#  Install add-apt-repository
#
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*

#  Requires GCC-4.9 as it has support for C11 keywords and atomics

#  For clang
RUN add-apt-repository -y "deb http://apt.llvm.org/${osname}/ llvm-toolchain-${osname}-${clangver} main" && \
    apt-key adv --fetch-keys http://apt.llvm.org/llvm-snapshot.gpg.key

RUN apt-get update && \
#  Development utilities
    apt-get install -y devscripts equivs git quilt && \
#  Compilers
    apt-get install -y g++-${gccver} llvm-${clangver} clang-${clangver} lldb-${clangver} && \
#  eapol_test dependencies
    apt-get install -y libnl-3-dev libnl-genl-3-dev

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-${gccver} 50 \
                        --slave /usr/bin/g++ g++ /usr/bin/g++-${gccver} && \
    update-alternatives --config gcc

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${clangver} 60 && \
    update-alternatives --config clang

RUN update-alternatives --install /usr/bin/lldb lldb /usr/bin/lldb-${clangver} 60 && \
    update-alternatives --config lldb


#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
RUN git clone --depth 1 --no-single-branch ${source}

#
#  Install build dependencies for all branches from v3 onwards
#
WORKDIR freeradius-server
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		if [ -e ./debian/control.in ] ; then debian/rules debian/control ; fi ; echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control ; \
	done
