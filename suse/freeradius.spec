#
# spec file for package freeradius (Version 0.8.1)
#
# Copyright (c) 2003 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://www.suse.de/feedback/
#

# neededforbuild  cyrus-sasl-devel db-devel heimdal-devel heimdal-lib libiodbc libiodbc-devel mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel postgresql postgresql-devel postgresql-libs python python-devel

Name:         freeradius
License:      GPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    radiusd-livingston radiusd-cistron icradius
Version:      0.9.0
Release:      0
URL:          http://www.freeradius.org/
Summary:      Very highly Configurable Radius-Server.
Source0:      %{name}-%{version}.tar.bz2
Source1:      rcradiusd
%if %suse_version > 800
PreReq:       %insserv_prereq %fillup_prereq
%endif
BuildRoot:    %{_tmppath}/%{name}-%{version}-build

%description
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods
Accounting methods



Authors:
--------
    Miquel van Smoorenburg <miquels@cistron.nl>
    Alan DeKok <aland@ox.org>
    Mike Machado <mike@innercite.com>
    Alan Curry
    various other people

%package devel
Group:        Development/Libraries/C and C++
Summary:      FreeRADIUS development files (static libs)

%description devel
These are the static libraries of the FreeRADIUS package



Authors:
--------
    Miquel van Smoorenburg <miquels@cistron.nl>
    Alan DeKok <aland@ox.org>
    Mike Machado <mike@innercite.com>
    Alan Curry
    various other people

%prep
%setup
rm -rf `find . -name CVS`

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure \
		--prefix=%{_prefix} \
                --sysconfdir=%{_sysconfdir} \
		--infodir=%{_infodir} \
		--mandir=%{_mandir} \
                --libdir=/usr/lib/freeradius \
		--localstatedir=/var \
		--with-threads \
		--with-thread-pool \
		--with-snmp \
		--with-large-files \
		--disable-ltdl-install \
		--with-ltdl-lib=/usr/lib \
		--with-ltdl-include=/usr/include \
		--with-gnu-ld \
		--enable-heimdal-krb5 \
		--with-rlm-krb5-include-dir=/usr/include/heimdal/ \
		--with-rlm-krb5-lib-dir=%{_libdir} \
		--enable-strict-dependencies
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf \
$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install R=$RPM_BUILD_ROOT
ldconfig -n $RPM_BUILD_ROOT/usr/lib/freeradius
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
# SuSE
install -d     $RPM_BUILD_ROOT/etc/pam.d
install -d     $RPM_BUILD_ROOT/etc/logrotate.d
install -m 644 suse/radiusd-pam $RPM_BUILD_ROOT/etc/pam.d/radiusd
install -m 644 suse/radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install    -m 744 %SOURCE1 $RPM_BUILD_ROOT/etc/init.d/radiusd
ln -sf ../../etc/init.d/radiusd $RPM_BUILD_ROOT/usr/sbin/rcradiusd
mv -v doc/README doc/README.doc
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/etc/raddb/experimental.conf $RPM_BUILD_ROOT/usr/sbin/radwatch $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/usr/share/doc/freeradius*

%post
%{fillup_and_insserv -s radiusd START_RADIUSD }

%postun
%{insserv_cleanup}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT

%files
# doc
%doc doc/* LICENSE COPYRIGHT CREDITS README
%doc src/modules/rlm_sql/drivers/rlm_sql_mysql/db_mysql.sql
%doc scripts/create-users.pl
%doc scripts/cryptpasswd scripts/exec-program-wait scripts/radiusd2ldif.pl
# SuSE
%config /etc/init.d/radiusd
%config /etc/pam.d/radiusd
%config /etc/logrotate.d/radiusd
/usr/sbin/rcradiusd
# configs
%dir /etc/raddb
%config /etc/raddb/dictionary
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%attr(640,root,root) %config(noreplace) /etc/raddb/clients
%attr(640,root,root) %config(noreplace) /etc/raddb/clients.conf
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%attr(640,root,root) %config(noreplace) /etc/raddb/mssql.conf
%config(noreplace) /etc/raddb/naslist
%attr(640,root,root) %config(noreplace) /etc/raddb/naspasswd
%attr(640,root,root) %config(noreplace) /etc/raddb/oraclesql.conf
%attr(640,root,root) %config(noreplace) /etc/raddb/postgresql.conf
%attr(640,root,root) %config(noreplace) /etc/raddb/preproxy_users
%attr(640,root,root) %config(noreplace) /etc/raddb/proxy.conf
%config(noreplace) /etc/raddb/radiusd.conf
%config(noreplace) /etc/raddb/realms
%attr(640,root,root) %config(noreplace) /etc/raddb/snmp.conf
%attr(640,root,root) %config(noreplace) /etc/raddb/sql.conf
%attr(640,root,root) %config(noreplace) /etc/raddb/users
%config(noreplace) /etc/raddb/x99.conf
%attr(640,root,root) %config(noreplace) /etc/raddb/x99passwd.sample
%dir /etc/raddb/certs
%config /etc/raddb/certs/README
%config(noreplace) /etc/raddb/certs/cert-clt.der
%config(noreplace) /etc/raddb/certs/cert-clt.p12
%config(noreplace) /etc/raddb/certs/cert-clt.pem
%config(noreplace) /etc/raddb/certs/cert-srv.der
%config(noreplace) /etc/raddb/certs/cert-srv.p12
%config(noreplace) /etc/raddb/certs/cert-srv.pem
%config(noreplace) /etc/raddb/certs/demoCA/cacert.pem
%config(noreplace) /etc/raddb/certs/demoCA/index.txt
%config(noreplace) /etc/raddb/certs/demoCA/index.txt.old
%config(noreplace) /etc/raddb/certs/demoCA/serial
%config(noreplace) /etc/raddb/certs/demoCA/serial.old
%config(noreplace) /etc/raddb/certs/dh
%config(noreplace) /etc/raddb/certs/newcert.pem
%config(noreplace) /etc/raddb/certs/newreq.pem
%config(noreplace) /etc/raddb/certs/random
%config(noreplace) /etc/raddb/certs/root.der
%config(noreplace) /etc/raddb/certs/root.p12
%config(noreplace) /etc/raddb/certs/root.pem
%attr(700,root,root) %dir /var/run/radiusd/
# binaries
/usr/bin/*
/usr/sbin/check-radiusd-config
/usr/sbin/checkrad
/usr/sbin/radiusd
# shared libs
%attr(755,root,root) %dir /usr/lib/freeradius
/usr/lib/freeradius/*.so*
/usr/lib/freeradius/*.la
# man-pages
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# dictionaries
%attr(755,root,root) %dir /usr/share/freeradius
/usr/share/freeradius/*
# logs
%attr(700,root,root) %dir /var/log/radius/
%attr(700,root,root) %dir /var/log/radius/radacct/
/var/log/radius/radutmp

%files devel
/usr/lib/freeradius/*.a
