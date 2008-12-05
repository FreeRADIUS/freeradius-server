Name:         freeradius-server
License:      GPL, LGPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    freeradius
Version:      2.1.3
Release:      0
URL:          http://www.freeradius.org/
Summary:      The world's most popular RADIUS Server
Source0:      %{name}-%{version}.tar.bz2

PreReq:       /usr/sbin/useradd /usr/sbin/groupadd
PreReq:       perl
%if %{?suse_version:1}0
PreReq:       %insserv_prereq %fillup_prereq
%endif

BuildRoot:    %{_tmppath}/%{name}-%{version}-build

%define _oracle_support	0

%define apxs2 apxs2-prefork
%define apache2_sysconfdir %(%{apxs2} -q SYSCONFDIR)
Requires:     %{name}-libs = %{version}
Requires:     python


BuildRequires: db-devel
BuildRequires: e2fsprogs-devel
BuildRequires: gcc-c++
BuildRequires: gdbm-devel
BuildRequires: gettext-devel
BuildRequires: glibc-devel
BuildRequires: libtool
BuildRequires: ncurses-devel
BuildRequires: openldap2-devel
BuildRequires: openssl-devel
BuildRequires: pam-devel
BuildRequires: libpcap
BuildRequires: perl
BuildRequires: postgresql-devel
BuildRequires: python-devel
BuildRequires: sed
BuildRequires: unixODBC-devel
BuildRequires: zlib-devel

%if %{?fedora_version:1}0
BuildRequires: cyrus-sasl-devel
BuildRequires: httpd-devel
BuildRequires: libtool-ltdl-devel
BuildRequires: perl-devel
BuildRequires: syslog-ng
BuildRequires: mysql-devel
%endif

%if %{?mandriva_version:1}0
BuildRequires: apache2-devel
BuildRequires: libtool-devel
BuildRequires: mysql-devel
%endif

%if %{?suse_version:1}0
BuildRequires: apache2-devel
BuildRequires: cyrus-sasl-devel
%if 0%{?suse_version} > 910
BuildRequires: bind-libs
BuildRequires: krb5-devel
%endif
%if 0%{?suse_version} > 930
BuildRequires: libcom_err
%endif
%if 0%{?suse_version} > 1000
BuildRequires: libapr1-devel
%endif
%if 0%{?suse_version} > 1020
BuildRequires: libmysqlclient-devel
%else
BuildRequires: mysql-devel
%endif
%endif

%description
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods
Accounting methods

%if %_oracle_support == 1
%package oracle
BuildRequires: oracle-instantclient-basic oracle-instantclient-devel
Group:        Productivity/Networking/Radius/Servers
Summary:      FreeRADIUS Oracle database support
Requires:     oracle-instantclient-basic
Requires:     %{name}-libs = %{version}
Requires:     %{name} = %{version}
Autoreqprov:  off

%description oracle
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods
%endif

%package libs
Group:        Productivity/Networking/Radius/Servers
Summary:      FreeRADIUS share library

%description libs
The FreeRADIUS shared library

%package utils
Group:        Productivity/Networking/Radius/Clients
Summary:      FreeRADIUS Clients
Requires:     %{name}-libs = %{version}

%description utils
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods

%package dialupadmin
Group:		Productivity/Networking/Radius/Servers
Summary:	Web management for FreeRADIUS
Requires:	http_daemon
Requires:	perl-DateManip
%if 0%{?suse_version} > 1000
Requires:	apache2-mod_php5
Requires:	php5
Requires:	php5-ldap
Requires:	php5-mysql
Requires:	php5-pgsql
%else
Requires:	apache2-mod_php4
Requires:	php4
Requires:	php4-ldap
Requires:	php4-mysql
Requires:	php4-pgsql
Requires:	php4-session
%endif
Autoreqprov:	off

%description dialupadmin
Dialup Admin supports users either in SQL (MySQL or PostgreSQL are
supported) or in LDAP. Apart from the web pages, it also includes a
number of scripts to make the administrator's life a lot easier.


%package devel
Group:        Development/Libraries/C and C++
Summary:      FreeRADIUS Development Files (static libs)
Autoreqprov:  off
Requires:     %{name}-libs = %{version}

%description devel
These are the static libraries for the FreeRADIUS package.


%if %{?suse_version:1}0
%debug_package
%endif

%prep
%setup -q

rm -rf `find . -name CVS`

%build
export CFLAGS="$RPM_OPT_FLAGS -fno-strict-aliasing -DLDAP_DEPRECATED -fPIC -DPIC"
#export CFLAGS="$CFLAGS -std=c99 -pedantic"
autoreconf

%configure \
		--libdir=%{_libdir}/freeradius \
                --disable-ltdl-install \
                --enable-developer \
		--with-edir \
		--with-experimental-modules \
		--with-system-libtool \
		--with-udpfromto \
		--without-rlm_eap_ikev2 \
		--without-rlm_opendirectory \
%if %{?fedora_version:1}0
                --with-rlm-krb5-include-dir=/usr/kerberos/include \
                --with-rlm-krb5-lib-dir=/usr/kerberos/lib \
%endif
%if %{?mandriva_version:1}0
		--without-rlm_dbm \
		--without-rlm_krb5 \
		--without-rlm_perl \
%endif
%if %{?suse_version:1}0
%if 0%{?suse_version} <= 920 
		--without-rlm_sql_mysql \
		--without-rlm_krb5 \
%endif
%endif
%if %_oracle_support == 1
		--with-rlm_sql_oracle \
		--with-oracle-lib-dir=%{_libdir}/oracle/10.1.0.3/client/lib/
%else
		--without-rlm_sql_oracle
%endif

# no parallel build possible
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/var/lib/radiusd
make install R=$RPM_BUILD_ROOT
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radrelay.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radrelay.conf
#ldconfig -n $RPM_BUILD_ROOT/usr/lib/freeradius
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
touch $RPM_BUILD_ROOT/var/log/radius/radius.log
# SuSE
install -d     $RPM_BUILD_ROOT/etc/pam.d
install -d     $RPM_BUILD_ROOT/etc/logrotate.d
%if 0%{?suse_version} > 920
install -m 644 suse/radiusd-pam $RPM_BUILD_ROOT/etc/pam.d/radiusd
%else
install -m 644 suse/radiusd-pam-old $RPM_BUILD_ROOT/etc/pam.d/radiusd
%endif
install -m 644 suse/radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install    -m 744 suse/rcradiusd $RPM_BUILD_ROOT/etc/init.d/freeradius
ln -sf ../../etc/init.d/freeradius $RPM_BUILD_ROOT/usr/sbin/rcfreeradius
cp $RPM_BUILD_ROOT/usr/sbin/radiusd $RPM_BUILD_ROOT/usr/sbin/radrelay
install    -m 744 suse/rcradius-relayd $RPM_BUILD_ROOT/etc/init.d/freeradius-relay
ln -sf ../../etc/init.d/freeradius-relay $RPM_BUILD_ROOT/usr/sbin/rcfreeradius-relay
mv -v doc/README doc/README.doc
# install dialup_admin
DIALUPADMIN=$RPM_BUILD_ROOT%{_datadir}/dialup_admin
mkdir -p $DIALUPADMIN
cp -r dialup_admin/* $RPM_BUILD_ROOT%{_datadir}/dialup_admin
perl -i -pe 's/^#general_base_dir\:.*$/general_base_dir\: \/usr\/share\/freeradius-dialupadmin/'   $DIALUPADMIN/conf/admin.conf
perl -i -pe 's/^#general_radiusd_base_dir\:.*$/general_radiusd_base_dir\: \//'   $DIALUPADMIN/conf/admin.conf
perl -i -pe 's/^#general_snmpwalk_command\:.*$/general_snmpwalk_command\: \/usr\/bin\/snmpwalk/'   $DIALUPADMIN/conf/admin.conf
perl -i -pe 's/^#general_snmpget_command\:.*$/general_snmpget_command\: \/usr\/bin\/snmpget/'   $DIALUPADMIN/conf/admin.conf
# apache2 config
install -d -m 755 $RPM_BUILD_ROOT%{apache2_sysconfdir}/conf.d
install -m 644 suse/admin-httpd.conf $RPM_BUILD_ROOT%{apache2_sysconfdir}/conf.d/radius.conf
# remove unneeded stuff
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/usr/share/doc/freeradius*
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la

%pre
/usr/sbin/groupadd -r radiusd 2> /dev/null || :
/usr/sbin/useradd -r -g radiusd -s /bin/false -c "Radius daemon" -d \
                  /var/lib/radiusd radiusd 2> /dev/null || :

%post
%ifarch x86_64
# Modify old installs to look for /usr/lib64/freeradius
/usr/bin/perl -i -pe "s:/usr/lib/freeradius:/usr/lib64/freeradius:" /etc/raddb/radiusd.conf
%endif

# Generate default certificates
/etc/raddb/certs/bootstrap

%{fillup_and_insserv -s freeradius START_RADIUSD }
%if 0%{?suse_version} > 820

%preun
%stop_on_removal freeradius
%endif

%postun
%if 0%{?suse_version} > 820
%restart_on_update freeradius
%endif
%{insserv_cleanup}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
# doc
%doc suse/README.SuSE
%doc doc/* LICENSE COPYRIGHT CREDITS README
%doc doc/examples/*
# SuSE
/etc/init.d/freeradius
/etc/init.d/freeradius-relay
%config /etc/pam.d/radiusd
%config /etc/logrotate.d/radiusd
/usr/sbin/rcfreeradius
/usr/sbin/rcfreeradius-relay
%dir %attr(755,radiusd,radiusd) /var/lib/radiusd
# configs
%dir %attr(750,-,radiusd) /etc/raddb
%defattr(-,root,radiusd)
%config(noreplace) /etc/raddb/dictionary
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%config(noreplace) /etc/raddb/attrs.access_reject
%config(noreplace) /etc/raddb/attrs.accounting_response
%config(noreplace) /etc/raddb/attrs.pre-proxy
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/clients.conf
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sqlippool.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/preproxy_users
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/proxy.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/radiusd.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql.conf
%dir %attr(640,-,radiusd) /etc/raddb/sql
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql/*/*.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql/*/*.sql
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql/oracle/msqlippool.txt
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/users
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/experimental.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/otp.conf
%dir %attr(750,-,radiusd) /etc/raddb/certs
/etc/raddb/certs/Makefile
/etc/raddb/certs/README
/etc/raddb/certs/xpextensions
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/certs/*.cnf
%attr(750,-,radiusd) /etc/raddb/certs/bootstrap
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sites-available/*
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/modules/*
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sites-enabled/*
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/eap.conf
%attr(640,-,radiusd) /etc/raddb/example.pl
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/policy.conf
/etc/raddb/policy.txt
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/templates.conf
%attr(700,radiusd,radiusd) %dir /var/run/radiusd/
# binaries
%defattr(-,root,root)
/usr/sbin/checkrad
/usr/sbin/radiusd
/usr/sbin/radrelay
/usr/sbin/radwatch
/usr/sbin/radmin
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
%config(noreplace) %attr(600,radiusd,radiusd) /var/log/radius/radius.log
# RADIUS Loadable Modules
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/rlm_*.so*

%files utils
/usr/bin/*

%files libs
# RADIU shared libs
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/lib*.so*

%if %_oracle_support == 1
%files oracle
%defattr(-,root,root)
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/rlm_sql_oracle*.so*
%endif

%files dialupadmin
%defattr(-,root,root)
%dir %{_datadir}/dialup_admin/
%{_datadir}/dialup_admin/Makefile
%{_datadir}/dialup_admin/bin/
%{_datadir}/dialup_admin/doc/
%{_datadir}/dialup_admin/htdocs/
%{_datadir}/dialup_admin/html/
%{_datadir}/dialup_admin/lib/
%{_datadir}/dialup_admin/sql/
%dir %{_datadir}/dialup_admin/conf/
%config(noreplace) %{_datadir}/dialup_admin/conf/*
%config(noreplace) %{apache2_sysconfdir}/conf.d/radius.conf
%{_datadir}/dialup_admin/Changelog
%{_datadir}/dialup_admin/README

%files devel
%defattr(-,root,root)
%attr(644,root,root) %{_libdir}/freeradius/*.a
#%attr(644,root,root) %{_libdir}/freeradius/*.la
%attr(644,root,root) /usr/include/freeradius/*.h
