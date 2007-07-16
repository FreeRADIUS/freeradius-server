%define _oracle_support	0

%define distroversion generic
%{!?suse_version:%define suse_version 0}
%{!?sles_version:%define sles_version 0}
%if %suse_version > 0
        %define distroversion   suse%{suse_version}
%endif
%if %sles_version > 0
        %define distroversion   sles%{sles_version}
%endif

Name:         freeradius
License:      GPL, LGPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    radiusd-livingston radiusd-cistron icradius
Version:      1.1.7
Release:      0.%{distroversion}
URL:          http://www.freeradius.org/
Summary:      Very highly Configurable Radius-Server
Conflicts:    freeradius-snapshot
Source:      %{name}-%{version}.tar.bz2

%if 0%{?suse_version} > 800
PreReq:       /usr/sbin/useradd /usr/sbin/groupadd
PreReq:       %insserv_prereq %fillup_prereq
PreReq:       perl
%endif
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
Autoreqprov:  off
%define apxs2 /usr/sbin/apxs2-prefork
%define apache2_sysconfdir %(%{apxs2} -q SYSCONFDIR)
Requires: python
%if %{?suse_version:1}0
BuildRequires: apache2-devel
%else
BuildRequires: httpd-devel
%endif

%if 0%{?sles_version} < 10
%else
BuildRequires: bind-libs
%endif
BuildRequires: cyrus-sasl-devel
BuildRequires: db-devel
BuildRequires: e2fsprogs-devel
BuildRequires: gcc-c++
BuildRequires: gdbm-devel
BuildRequires: gettext-devel
BuildRequires: glibc-devel
BuildRequires: libtool
BuildRequires: mysql-devel
BuildRequires: ncurses-devel
BuildRequires: net-snmp-devel
BuildRequires: openldap2-devel
BuildRequires: openssl-devel
BuildRequires: pam-devel
BuildRequires: perl
BuildRequires: postgresql-devel
BuildRequires: python-devel
BuildRequires: sed
BuildRequires: unixODBC-devel
BuildRequires: zlib-devel

%if 0%{?suse_version} > 910
BuildRequires: krb5-devel
%endif

%if 0%{?suse_version} > 930

BuildRequires: libcom_err
%if %suse_version > 1000
BuildRequires: libapr1-devel
%else
#BuildRequires: libapr0-devel
%endif

%endif

%if 0%{?fedora_version} > 4
BuildRequires: syslog-ng
%endif


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

%if %_oracle_support == 1
%package oracle
BuildRequires: oracle-instantclient-basic oracle-instantclient-devel
Group:        Productivity/Networking/Radius/Servers
Summary:      FreeRADIUS Oracle database support
Requires:     oracle-instantclient-basic
Autoreqprov:  off

%description oracle
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods
%endif

%package dialupadmin
Group:          Productivity/Networking/Radius/Servers
Summary:        Web management for FreeRADIUS
Requires:       http_daemon
Requires:       perl-DateManip
%if 0%{?suse_version} > 1000
Requires:       apache2-mod_php5
Requires:       php5
Requires:       php5-ldap
Requires:       php5-mysql
Requires:       php5-pgsql
%else
Requires:       apache2-mod_php4
Requires:       php4
Requires:       php4-ldap
Requires:       php4-mysql
Requires:       php4-pgsql
Requires:       php4-session
%endif
Autoreqprov:    off

%description dialupadmin
Dialup Admin supports users either in SQL (MySQL or PostgreSQL are
supported) or in LDAP. Apart from the web pages, it also includes a
number of scripts to make the administrator's life a lot easier.



Authors:
--------
    Kostas Kalevras <kkalev at noc.ntua.gr>
    Basilis Pappas <vpappas at noc.ntua.gr>
    Panagiotis Christias <christia at noc.ntua.gr>
    Thanasis Duitsis <aduitsis at noc.ntua.gr>

%package devel
Group:        Development/Libraries/C and C++
Summary:      FreeRADIUS Development Files (static libs)
Autoreqprov:  off

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
%setup -q
rm -rf `find . -name CVS`


%build
export CFLAGS="$RPM_OPT_FLAGS -fno-strict-aliasing -DLDAP_DEPRECATED"
%ifarch x86_64
export CFLAGS="$CFLAGS -fPIC"
%endif
%if 0%{?suse_version} > 1000
export CFLAGS="$CFLAGS -fstack-protector"
%endif
./configure \
	 	--prefix=%{_prefix} \
                --sysconfdir=%{_sysconfdir} \
		--infodir=%{_infodir} \
		--mandir=%{_mandir} \
		--localstatedir=/var \
		--libdir=%{_libdir}/freeradius \
		--with-threads \
		--with-snmp \
		--with-large-files \
%if 0%{?suse_version} <= 920 
		--without-rlm_sql_mysql \
%endif
%if %{?suse_version:1}0
%if %suse_version > 910
%if %suse_version <= 920
		--enable-heimdal-krb5 \
		--with-rlm-krb5-include-dir=/usr/include/heimdal/ \
%endif
		--with-rlm-krb5-lib-dir=%{_libdir} \
%else
		--without-rlm_krb5 \
%endif
%endif
%if %_oracle_support == 1
		--with-rlm_sql_oracle \
		--with-oracle-lib-dir=%{_libdir}/oracle/10.1.0.3/client/lib/ \
%else
		--without-rlm_sql_oracle \
%endif
		--enable-strict-dependencies \
		--with-edir \
		--with-modules="rlm_sqlippool" \
		--disable-ltdl-install \
		--with-gnu-ld \
		--with-udpfromto
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
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
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
install    -m 744 suse/rcradiusd $RPM_BUILD_ROOT/etc/init.d/radiusd
ln -sf ../../etc/init.d/radiusd $RPM_BUILD_ROOT/usr/sbin/rcradiusd
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
rm -f $RPM_BUILD_ROOT/etc/raddb/experimental.conf $RPM_BUILD_ROOT/usr/sbin/radwatch $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/usr/share/doc/freeradius*
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la

%pre
/usr/sbin/groupadd -r radiusd 2> /dev/null || :
/usr/sbin/useradd -r -g radiusd -s /bin/false -c "Radius daemon" -d \
                  /var/lib/radiusd radiusd 2> /dev/null || :

%post
%ifarch x86_64
# Modify old installs to look for /usr/lib64/freeradius
#libdir32=${%{_libdir}%%64}/freeradius
/usr/bin/perl -i -pe "s:/usr/lib/freeradius:/usr/lib64/freeradius:" /etc/raddb/radiusd.conf
%endif

%{fillup_and_insserv -s radiusd START_RADIUSD }
%if 0%{?suse_version} > 820

%preun
%stop_on_removal radiusd
%endif

%postun
%if 0%{?suse_version} > 820
%restart_on_update radiusd
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
%doc scripts/create-users.pl scripts/CA.* scripts/certs.sh
%doc scripts/users2mysql.pl scripts/xpextensions
%doc scripts/cryptpasswd scripts/exec-program-wait scripts/radiusd2ldif.pl
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
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sqlippool.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/preproxy_users
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/proxy.conf
%config(noreplace) /etc/raddb/radiusd.conf
%ghost %config(noreplace) /etc/raddb/realms
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/snmp.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/sql.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/users
%config(noreplace) /etc/raddb/otp.conf
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/certs
%attr(640,-,radiusd) %config(noreplace) /etc/raddb/eap.conf
%attr(640,-,radiusd) /etc/raddb/example.pl
%attr(700,radiusd,radiusd) %dir /var/run/radiusd/
# binaries
%defattr(-,root,root)
/usr/bin/*
/usr/sbin/check-radiusd-config
/usr/sbin/checkrad
/usr/sbin/radiusd
# shared libs
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/*.so*
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

%if %_oracle_support == 1
%files oracle
%defattr(-,root,root)
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/rlm_sql_oracle*.so*
%endif

%files dialupadmin
%defattr(-,root,root)
%dir %{_datadir}/dialup_admin/
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
%{_libdir}/freeradius/*.a
#%attr(644,root,root) %{_libdir}/freeradius/*.la
