#
# spec file for package freeradius-server (Version 2.1.8)
#



Name:         freeradius-server
Version:      2.2.0
Release:      0
License:      GPLv2 ; LGPLv2.1
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Provides:     freeradius = %{version}
Obsoletes:    freeradius < %{version}
Conflicts:    radiusd-livingston radiusd-cistron icradius
Url:          http://www.freeradius.org/
Summary:      Very Highly Configurable Radius Server
Source:       ftp://ftp.freeradius.org/pub/freeradius/%{name}-%{version}.tar.bz2
Source90:     %{name}-rpmlintrc
Source104:    %{name}-tmpfiles.conf
Patch0:       freeradius-server-2.1.6-suseinit.patch
PreReq:       /usr/sbin/useradd /usr/sbin/groupadd
PreReq:       perl
PreReq:       %insserv_prereq %fillup_prereq
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
%define _oracle_support	0
%define apxs2 apxs2-prefork
%define apache2_sysconfdir %(%{_sbindir}/%{apxs2} -q SYSCONFDIR)
Requires:      %{name}-libs = %{version}
Requires:      python
Recommends:    logrotate
BuildRequires: apache2-devel 
BuildRequires: cyrus-sasl-devel
BuildRequires: db-devel
BuildRequires: gcc-c++
BuildRequires: gdbm-devel
BuildRequires: gettext-devel
BuildRequires: glibc-devel
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: ncurses-devel
BuildRequires: net-snmp-devel
BuildRequires: openldap2-devel
BuildRequires: openssl
BuildRequires: openssl-devel
BuildRequires: pam-devel
BuildRequires: perl
BuildRequires: postgresql-devel
BuildRequires: python-devel
BuildRequires: sed
BuildRequires: sqlite3-devel
BuildRequires: unixODBC-devel


%if 0%{?suse_version} > 910
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

%description oracle
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods
%endif

%package libs
License:      GPLv2 ; LGPLv2.1
Group:        Productivity/Networking/Radius/Servers
Summary:      FreeRADIUS shared library

%description libs
The FreeRADIUS shared library



Authors:
--------
    Miquel van Smoorenburg <miquels@cistron.nl>
    Alan DeKok <aland@ox.org>
    Mike Machado <mike@innercite.com>
    Alan Curry
    various other people

%package utils
License:      GPLv2 ; LGPLv2.1
Group:        Productivity/Networking/Radius/Clients
Summary:      FreeRADIUS Clients
Requires:     %{name}-libs = %{version}

%description utils
The FreeRADIUS server has a number of features found in other servers
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods

%package dialupadmin
License:    GPLv2 ; LGPLv2.1
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
License:        GPLv2 ; LGPLv2.1
Group:        Development/Libraries/C and C++
Summary:      FreeRADIUS Development Files (static libs)
Requires:     %{name}-libs = %{version}

%description devel
These are the static libraries for the FreeRADIUS package.



Authors:
--------
    Miquel van Smoorenburg <miquels@cistron.nl>
    Alan DeKok <aland@ox.org>
    Mike Machado <mike@innercite.com>
    Alan Curry
    various other people

%package doc
License:        GPLv2 ; LGPLv2.1
Group:          Productivity/Networking/Radius/Servers
Summary:        FreeRADIUS Documentation
Requires:       %{name}

%description doc
This package contains FreeRADIUS Documentation



Authors:
--------
    Miquel van Smoorenburg <miquels@cistron.nl>
    Alan DeKok <aland@ox.org>
    Mike Machado <mike@innercite.com>
    Alan Curry
    various other people

%prep
%setup -q
%patch0

%build
# This package failed when testing with -Wl,-as-needed being default.
# So we disable it here, if you want to retest, just delete this comment and the line below.
export SUSE_ASNEEDED=0
export CFLAGS="$RPM_OPT_FLAGS -fstack-protector -fno-strict-aliasing"
%ifarch x86_64 ppc ppc64 s390 s390x
export CFLAGS="$CFLAGS -fPIC -DPIC"
%endif
export LDFLAGS="-pie"
%configure \
		--libdir=%{_libdir}/freeradius \
        --disable-ltdl-install \
		--with-edir \
		--with-experimental-modules \
        --with-gnu-ld \
		--with-system-libtool \
		--with-system-libltdl \
        --with-udpfromto \
        --with-rlm-krb5-lib-dir=%{_libdir} \
		--without-rlm_opendirectory \
		--without-rlm_sqlhpwippool \
%if 0%{?suse_version} <= 920 
		--without-rlm_sql_mysql \
		--without-rlm_krb5 \
%endif
%if %{_oracle_support} == 1
		--with-rlm_sql_oracle \
		--with-oracle-lib-dir=%{_libdir}/oracle/10.1.0.3/client/lib/
%else
		--without-rlm_sql_oracle
%endif
# no parallel build possible
make

%install
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/radiusd
make install R=$RPM_BUILD_ROOT INSTALLSTRIP=
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
/sbin/ldconfig -n $RPM_BUILD_ROOT%{_libdir}/freeradius
# logs
touch $RPM_BUILD_ROOT%{_localstatedir}/log/radius/radutmp
touch $RPM_BUILD_ROOT%{_localstatedir}/log/radius/radius.log
# SuSE
install -d     $RPM_BUILD_ROOT%{_sysconfdir}/pam.d
install -d     $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -m 644 suse/radiusd-pam $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/radiusd
install -m 644 suse/radiusd-logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/freeradius-server
install -d -m 755 $RPM_BUILD_ROOT%{_sysconfdir}/init.d
#install    -m 744 suse/rcradiusd $RPM_BUILD_ROOT%{_sysconfdir}/init.d/freeradius
#ln -sf ../..%{_sysconfdir}/init.d/freeradius $RPM_BUILD_ROOT%{_sbindir}/rcfreeradius
install    -m 744 suse/rcradiusd $RPM_BUILD_ROOT%{_sysconfdir}/init.d/radiusd
ln -sf ../..%{_sysconfdir}/init.d/radiusd $RPM_BUILD_ROOT%{_sbindir}/rcradiusd
install -d %{buildroot}%{_sysconfdir}/tmpfiles.d
install -m 0644 %{SOURCE104} %{buildroot}%{_sysconfdir}/tmpfiles.d/radiusd.conf

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
rm -f $RPM_BUILD_ROOT%{_sbindir}/rc.radiusd
rm -rf $RPM_BUILD_ROOT%{_datadir}/doc/freeradius*
rm -rf $RPM_BUILD_ROOT%{_libdir}/freeradius/*.*a

%pre
%{_sbindir}/groupadd -r radiusd 2> /dev/null || :
%{_sbindir}/useradd -r -g radiusd -s /bin/false -c "Radius daemon" -d \
                  %{_localstatedir}/lib/radiusd radiusd 2> /dev/null || :

%post
%ifarch x86_64
# Modify old installs to look for /usr/lib64/freeradius
/usr/bin/perl -i -pe "s:/usr/lib/freeradius:/usr/lib64/freeradius:" /etc/raddb/radiusd.conf
%endif

# Generate default certificates
if [ $1 -eq 1 ]; then
    /etc/raddb/certs/bootstrap
fi
chgrp radiusd /etc/raddb/certs/*
%{fillup_and_insserv radiusd}

%preun
%stop_on_removal radiusd

%postun
%restart_on_update radiusd
%{insserv_cleanup}

%clean
rm -rf $RPM_BUILD_ROOT

%files doc
%defattr(-,root,root)
%doc doc/*

%files
%defattr(-,root,root)
# doc
%doc suse/README.SuSE
%doc COPYRIGHT CREDITS LICENSE README doc/ChangeLog
%doc doc/examples/*
# SuSE
#%{_sysconfdir}/init.d/freeradius
%{_sysconfdir}/init.d/radiusd
%config %{_sysconfdir}/pam.d/radiusd
%config %{_sysconfdir}/logrotate.d/freeradius-server
%config %{_sysconfdir}/tmpfiles.d/radiusd.conf
%{_sbindir}/rcradiusd
%dir %attr(755,radiusd,radiusd) %{_localstatedir}/lib/radiusd
# configs
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb
%defattr(-,root,radiusd)
%config(noreplace) %{_sysconfdir}/raddb/dictionary
%config(noreplace) %{_sysconfdir}/raddb/acct_users
%config(noreplace) %{_sysconfdir}/raddb/attrs
%config(noreplace) %{_sysconfdir}/raddb/attrs.access_reject
%config(noreplace) %{_sysconfdir}/raddb/attrs.accounting_response
%config(noreplace) %{_sysconfdir}/raddb/attrs.pre-proxy
%config(noreplace) %{_sysconfdir}/raddb/attrs.access_challenge
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/clients.conf
%config(noreplace) %{_sysconfdir}/raddb/hints
%config(noreplace) %{_sysconfdir}/raddb/huntgroups
%config(noreplace) %{_sysconfdir}/raddb/ldap.attrmap
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sqlippool.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/preproxy_users
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/proxy.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/radiusd.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sql.conf
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/modules
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/modules/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql/mssql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql/mysql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql/oracle
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql/postgresql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sql/ndb
%{_sysconfdir}/raddb/sql/ndb/README
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sql/*/*.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sql/*/*.sql
%{_sysconfdir}/raddb/sql/oracle/msqlippool.txt
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/users
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/experimental.conf
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/certs
%{_sysconfdir}/raddb/certs/Makefile
%{_sysconfdir}/raddb/certs/README
%{_sysconfdir}/raddb/certs/xpextensions
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/*.cnf
%attr(750,root,radiusd) %{_sysconfdir}/raddb/certs/bootstrap
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-available
%attr(640,root,radiusd) %{_sysconfdir}/raddb/sites-available/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-enabled
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sites-enabled/*
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/eap.conf
%attr(640,root,radiusd) %{_sysconfdir}/raddb/example.pl
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/policy.conf
%{_sysconfdir}/raddb/policy.txt
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/templates.conf
%attr(700,radiusd,radiusd) %dir %{_localstatedir}/run/radiusd/
# binaries
%defattr(-,root,root)
%{_sbindir}/checkrad
%{_sbindir}/radiusd
%{_sbindir}/radmin
%{_sbindir}/radwatch
%{_sbindir}/raddebug
# man-pages
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# dictionaries
%attr(755,root,root) %dir %{_datadir}/freeradius
%{_datadir}/freeradius/*
# logs
%attr(700,radiusd,radiusd) %dir %{_localstatedir}/log/radius/
%attr(700,radiusd,radiusd) %dir %{_localstatedir}/log/radius/radacct/
%attr(644,radiusd,radiusd) %{_localstatedir}/log/radius/radutmp
%config(noreplace) %attr(600,radiusd,radiusd) %{_localstatedir}/log/radius/radius.log
# RADIUS Loadable Modules
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/rlm_*.so*

%files utils
%defattr(-,root,root)
%doc %{_mandir}/man1/*
%{_bindir}/*

%files libs
%defattr(-,root,root)
# RADIUS shared libs
%attr(755,root,root) %dir %{_libdir}/freeradius
%attr(755,root,root) %{_libdir}/freeradius/lib*.so*
%if %{_oracle_support} == 1

%files oracle
%defattr(-,radiusd,radiusd)
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
%dir %attr(755,root,root) %{_includedir}/freeradius
%attr(644,root,root) %{_includedir}/freeradius/*.h

%changelog
* Fri Feb 10 2012 nix@opensuse.org
- Add a /var/run/radiusd tmpfile.d config
- Add -fno-strict-aliasing to compiler flags to fix warning
- Remove -DLDAP_DEPRECATED from compiler flags
- Disable rlm_sqlhpwippool as there don't seem to be many users and
  it is throwing a compiler warning at present
* Tue Feb  7 2012 nix@opensuse.org
- addFilter("dir-or-file-in-var-run") to rpmlintrc to enable builds
  on newer versions of openSUSE. Need to investigate fixing this..
* Tue Feb  7 2012 nix@opensuse.org
- Rename freeradius init script to radiusd to match package standards
* Tue Feb  7 2012 nix@opensuse.org
- rename logrotate script to match package name
* Tue Feb  7 2012 nix@opensuse.org
- Remove radrelay related stuff as it is now handled internallly
  rather than as a separate process
* Sat Nov 19 2011 nix@opensuse.org
- Update to version 2.1.12
* Tue Aug 23 2011 nix@opensuse.org
- Update to version 2.1.11
* Wed Mar 17 2010 puzel@novell.com
- remove unused patches:
  - freeradius-1.1.0-python.patch
  - ltdl.patch
  - radius_logger_apn.patch
  - token-support-freeradius-1.1.6.patch
- specfile cleanup as preparation to merge with
  obs://networking/freeradius-server
* Wed Mar 10 2010 nix@opensuse.org
- Upgrade to version 2.1.8
