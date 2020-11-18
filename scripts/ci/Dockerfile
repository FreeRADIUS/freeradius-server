FROM ubuntu:14.04
RUN apt-get update && apt-get install -y curl
RUN curl -sSL "https://build.travis-ci.org/files/gpg/couchbase-precise.asc" | sudo -E apt-key add -
RUN echo "deb http://packages.couchbase.com/ubuntu precise precise/main" | sudo tee -a /etc/apt/sources.list >/dev/null
RUN echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-5.0 main" >> /etc/apt/sources.list
RUN curl https://raw.githubusercontent.com/travis-ci/apt-source-safelist/master/keys/llvm-toolchain-trusty-5.0.asc | apt-key add -
RUN apt-get update && apt-get -y upgrade
RUN apt-get -yq --no-install-suggests --no-install-recommends install autoconf build-essential debhelper devscripts dh-make doxygen fakeroot gdb graphviz lintian pbuilder python-dev quilt libruby ruby-dev libcollectdclient-dev firebird-dev freetds-dev libcap-dev libcouchbase2-libevent libcouchbase-dev libcurl4-openssl-dev libgdbm-dev libhiredis-dev libidn11-dev libiodbc2-dev libiodbc2 libjson0 libjson0-dev libkrb5-dev libldap2-dev libmemcached-dev libmysqlclient-dev libpam0g-dev libpcap-dev libpcre3-dev libperl-dev libpq-dev libreadline-dev libsnmp-dev libssl-dev libtalloc-dev libtalloc2-dbg libunbound-dev libwbclient-dev libykclient-dev libyubikey-dev clang-5.0
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-5.0 100
WORKDIR /usr/local/src/repositories
