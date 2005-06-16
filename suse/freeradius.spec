#
# spec file for package freeradius (Version 1.0.2)
#
# Copyright (c) 2004 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://www.suse.de/feedback/
#

# neededforbuild  cyrus-sasl-devel db-devel heimdal-devel heimdal-lib mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel pam-devel postgresql postgresql-devel postgresql-libs python python-devel unixODBC unixODBC-devel

BuildRequires: aaa_base acl attr bash bind-utils bison bzip2 coreutils cpio cpp cracklib cvs cyrus-sasl db devs diffutils e2fsprogs file filesystem fillup findutils flex gawk gdbm-devel glibc glibc-devel glibc-locale gpm grep groff gzip info insserv less libacl libattr libgcc libnscd libselinux libstdc++ libxcrypt libzio m4 make man mktemp module-init-tools ncurses ncurses-devel net-tools netcfg openldap2-client openssl pam pam-modules patch permissions popt procinfo procps psmisc pwdutils rcs readline sed strace syslogd sysvinit tar tcpd texinfo timezone unzip util-linux vim zlib zlib-devel autoconf automake binutils cyrus-sasl-devel db-devel e2fsprogs-devel gcc gdbm gettext heimdal-devel heimdal-lib libtool mysql-devel mysql-shared openldap2 openldap2-devel openssl-devel pam-devel perl postgresql postgresql-devel postgresql-libs python python-devel rpm unixODBC unixODBC-devel

Name:         freeradius
License:      GPL, LGPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    radiusd-livingston radiusd-cistron icradius
Version:      1.0.4
Release:      1.suse
URL:          http://www.freeradius.org/
Summary:      Very highly Configurable Radius-Server
Source0:      %{name}-%{version}.tar.gz
%if %suse_version > 800
PreReq:       /usr/sbin/useradd /usr/sbin/groupadd
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
Summary:      FreeRADIUS Development Files (static libs)

%description devel
These are the static libraries for the FreeRADIUS package.



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
CFLAGS="$RPM_OPT_FLAGS -fno-strict-aliasing" ./configure \
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
mkdir -p $RPM_BUILD_ROOT/var/lib/radiusd
make install R=$RPM_BUILD_ROOT
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
ldconfig -n $RPM_BUILD_ROOT/usr/lib/freeradius
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
# SuSE
install -d     $RPM_BUILD_ROOT/etc/pam.d
install -d     $RPM_BUILD_ROOT/etc/logrotate.d
install -m 644 suse/radiusd-pam $RPM_BUILD_ROOT/etc/pam.d/radiusd
install -m 644 suse/radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install    -m 744 suse/rcradiusd $RPM_BUILD_ROOT/etc/init.d/radiusd
ln -sf ../../etc/init.d/radiusd $RPM_BUILD_ROOT/usr/sbin/rcradiusd
mv -v doc/README doc/README.doc
# remove unneeded stuff
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/etc/raddb/experimental.conf $RPM_BUILD_ROOT/usr/sbin/radwatch $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/usr/share/doc/freeradius*

%pre
/usr/sbin/groupadd -r radiusd 2> /dev/null || :
/usr/sbin/useradd -r -g radiusd -s /bin/false -c "Radius daemon" -d \
                  /var/lib/radiusd radiusd 2> /dev/null || :

%post
%{fillup_and_insserv -s radiusd START_RADIUSD }
%if %suse_version > 820

%preun
%stop_on_removal radiusd
%endif

%postun
%if %suse_version > 820
%restart_on_update radiusd
%endif
%{insserv_cleanup}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
# doc
%doc %attr(-,root,root) $RPM_SOURCE_DIR/README.SuSE
%doc doc/* LICENSE COPYRIGHT CREDITS README
%doc src/modules/rlm_sql/drivers/rlm_sql_*/*.sql
%doc scripts/create-users.pl scripts/CA.* scripts/certs.sh
%doc scripts/users2mysql.pl scripts/xpextensions
%doc scripts/cryptpasswd scripts/exec-program-wait scripts/radiusd2ldif.pl
%doc dialup_admin
# SuSE
%config /etc/init.d/radiusd
%config /etc/pam.d/radiusd
%config /etc/logrotate.d/radiusd
/usr/sbin/rcradiusd
%dir %attr(755,radiusd,radiusd) /var/lib/radiusd
# configs
%dir /etc/raddb
%defattr(-,root,radiusd)
%config /etc/raddb/dictionary
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%attr(640,-,radiusd) %ghost %config(noreplace) /etc/raddb/clients
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/clients.conf
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/mssql.conf
%ghost %config(noreplace) /etc/raddb/naslist
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/naspasswd
%attr(640,-,radiusd) %ghost %config(noreplace) /etc/raddb/oraclesql.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/postgresql.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/preproxy_users
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/proxy.conf
%config(noreplace) /etc/raddb/radiusd.conf
%ghost %config(noreplace) /etc/raddb/realms
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/snmp.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/users
%config(noreplace) /etc/raddb/x99.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/x99passwd.sample
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/certs
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/eap.conf
%attr(700,radiusd,radiusd) %dir /var/run/radiusd/
# binaries
%defattr(-,root,root)
/usr/bin/*
/usr/sbin/check-radiusd-config
/usr/sbin/checkrad
/usr/sbin/radiusd
# shared libs
%attr(755,root,root) %dir /usr/lib/freeradius
%attr(755,root,root) /usr/lib/freeradius/*.so*
%attr(644,root,root) /usr/lib/freeradius/*.la
# man-pages
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# dictionaries
%attr(755,root,root) %dir /usr/share/freeradius
/usr/share/freeradius/*
# logs
%attr(700,radiusd,radiusd) %dir /var/log/radius/
%attr(700,radiusd,radiusd) %dir /var/log/radius/radacct/
%attr(644,radiusd,radiusd) /var/log/radius/radutmp

%files devel
%defattr(-,root,root)
/usr/lib/freeradius/*.a

