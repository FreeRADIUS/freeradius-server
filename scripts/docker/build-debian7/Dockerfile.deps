FROM debian:wheezy

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y sudo firebird-dev freetds-dev libcap-dev libcollectdclient-dev libcurl4-openssl-dev libgdbm-dev libhiredis-dev libidn11-dev libiodbc2-dev libjson0-dev libldap2-dev libpq-dev libmemcached-dev libmysqlclient-dev libpam0g-dev libpcap-dev libperl-dev libsqlite3-dev libunbound-dev libtalloc-dev libwbclient-dev libykclient-dev libyubikey-dev python-dev ruby ruby-dev snmp software-properties-common python-software-properties libssl-dev libtalloc-dev libkqueue-dev make packaging-dev libkrb5-dev libreadline-dev samba4-dev openssh-server mercurial

#
#  Install GCC-4.9 as it has the requisite support for C11 keywords and atomics
#

#
#  Install eapol_test dependencies
#
RUN apt-get install -y libnl-3-dev libnl-genl-3-dev

#
#  Setup a src dir in /usr/local
#
WORKDIR /usr/local/src/repositories
RUN git clone --depth=1 --no-single-branch https://github.com/FreeRADIUS/freeradius-server.git
WORKDIR freeradius-server

# Install build dependencies for all branches
RUN for i in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null | sed -e 's#origin/##' | egrep "^(v[3-9]*\.[0-9x]*\.x|master)$");\
	do \
		git checkout $i; \
		[ -e ./debian/control.in ] && debian/rules debian/control; \
		echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control; \
	done

