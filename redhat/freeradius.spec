Summary: High-performance and highly configurable free RADIUS server
Name: freeradius
Version: 2.2.10
Release: 1%{?dist}
License: GPLv2+ and LGPLv2+
Group: System Environment/Daemons
URL: http://www.freeradius.org/

Source0: ftp://ftp.freeradius.org/pub/radius/freeradius-server-%{version}.tar.bz2
Source100: freeradius-radiusd-init
Source102: freeradius-logrotate
Source103: freeradius-pam-conf

Patch1: freeradius-cert-config.patch

Obsoletes: freeradius-devel
Obsoletes: freeradius-libs

%define docdir %{_docdir}/freeradius-%{version}
%define initddir %{?_initddir:%{_initddir}}%{!?_initddir:%{_initrddir}}

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf
BuildRequires: gdbm-devel
BuildRequires: libtool
BuildRequires: libtool-ltdl-devel
BuildRequires: make
BuildRequires: openssl-devel
BuildRequires: pam-devel
BuildRequires: zlib-devel
BuildRequires: net-snmp-devel
BuildRequires: net-snmp-utils
BuildRequires: readline-devel
BuildRequires: libpcap-devel

Requires(pre): shadow-utils glibc-common
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig

%description
The FreeRADIUS Server Project is a high performance and highly configurable
GPL'd free RADIUS server. The server is similar in some respects to
Livingston's 2.0 server.  While FreeRADIUS started as a variant of the
Cistron RADIUS server, they don't share a lot in common any more. It now has
many more features than Cistron or Livingston, and is much more configurable.

FreeRADIUS is an Internet authentication daemon, which implements the RADIUS
protocol, as defined in RFC 2865 (and others). It allows Network Access
Servers (NAS boxes) to perform authentication for dial-up users. There are
also RADIUS clients available for Web servers, firewalls, Unix logins, and
more.  Using RADIUS allows authentication and authorization for a network to
be centralized, and minimizes the amount of re-configuration which has to be
done when adding or deleting new users.

%package utils
Group: System Environment/Daemons
Summary: FreeRADIUS utilities
Requires: %{name} = %{version}-%{release}
Requires: libpcap >= 0.9.4

%description utils
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods

%package ldap
Summary: LDAP support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: openldap-devel

%description ldap
This plugin provides the LDAP support for the FreeRADIUS server project.

%package krb5
Summary: Kerberos 5 support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: krb5-devel

%description krb5
This plugin provides the Kerberos 5 support for the FreeRADIUS server project.

%package perl
Summary: Perl support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%{?fedora:BuildRequires: perl-devel}
%if 0%{?rhel} <= 5
BuildRequires: perl
%endif
%if 0%{?rhel} >= 6
BuildRequires: perl-devel
%endif
BuildRequires: perl(ExtUtils::Embed)

%description perl
This plugin provides the Perl support for the FreeRADIUS server project.

%package python
Summary: Python support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: python-devel

%description python
This plugin provides the Python support for the FreeRADIUS server project.

%package mysql
Summary: MySQL support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: mysql-devel

%description mysql
This plugin provides the MySQL support for the FreeRADIUS server project.

%package postgresql
Summary: Postgresql support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: postgresql-devel

%description postgresql
This plugin provides the postgresql support for the FreeRADIUS server project.

%package unixODBC
Summary: Unix ODBC support for freeradius
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
BuildRequires: unixODBC-devel

%description unixODBC
This plugin provides the unixODBC support for the FreeRADIUS server project.


%prep
%setup -q -n freeradius-server-%{version}
%patch1 -p1 -b .cert-config

# Some source files mistakenly have execute permissions set
find $RPM_BUILD_DIR/freeradius-server-%{version} \( -name '*.c' -o -name '*.h' \) -a -perm /0111 -exec chmod a-x {} +

%build
%ifarch s390 s390x
export CFLAGS="$RPM_OPT_FLAGS -fPIC"
%else
export CFLAGS="$RPM_OPT_FLAGS -fpic"
%endif

%configure \
        --libdir=%{_libdir}/freeradius \
        --with-system-libtool \
        --with-system-libltdl \
        --disable-ltdl-install \
        --with-udpfromto \
        --with-gnu-ld \
        --with-threads \
        --with-thread-pool \
        --with-docdir=%{docdir} \
        --with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
        --with-rlm-sql-postgresql-lib-dir=%{_libdir} \
        --with-rlm-sql_mysql-include-dir=/usr/include/mysql \
        --with-mysql-lib-dir=%{_libdir}/mysql \
        --with-unixodbc-lib-dir=%{_libdir} \
        --with-rlm-dbm-lib-dir=%{_libdir} \
        --with-rlm-krb5-include-dir=/usr/kerberos/include \
        --with-modules="rlm_wimax" \
        --without-rlm_eap_ikev2 \
        --without-rlm_sql_iodbc \
        --without-rlm_sql_firebird \
        --without-rlm_sql_db2 \
        --without-rlm_sql_oracle

%if "%{_lib}" == "lib64"
perl -pi -e 's:sys_lib_search_path_spec=.*:sys_lib_search_path_spec="/lib64 /usr/lib64 /usr/local/lib64":' libtool
%endif

make LINK_MODE=-pie

%install
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/lib/radiusd
# fix for bad libtool bug - can not rebuild dependent libs and bins
#FIXME export LD_LIBRARY_PATH=$RPM_BUILD_ROOT/%{_libdir}
make install R=$RPM_BUILD_ROOT
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
# logs
mkdir -p $RPM_BUILD_ROOT/var/log/radius/radacct
touch $RPM_BUILD_ROOT/var/log/radius/{radutmp,radius.log}

install -D -m 755 %{SOURCE100} $RPM_BUILD_ROOT/%{initddir}/radiusd
install -D -m 644 %{SOURCE102} $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/radiusd
install -D -m 644 %{SOURCE103} $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/radiusd

mkdir -p %{buildroot}%{_localstatedir}/run/
install -d -m 0710 %{buildroot}%{_localstatedir}/run/radiusd/

# remove unneeded stuff
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.a
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/sql/mssql
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/sql/oracle
rm -rf $RPM_BUILD_ROOT/%{_datadir}/dialup_admin/sql/oracle
rm -rf $RPM_BUILD_ROOT/%{_datadir}/dialup_admin/lib/sql/oracle
rm -rf $RPM_BUILD_ROOT/%{_datadir}/dialup_admin/lib/sql/drivers/oracle

# remove header files, we don't ship a devel package and the
# headers have multilib conflicts
rm -rf $RPM_BUILD_ROOT/%{_includedir}

# remove unsupported config files
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/experimental.conf

# install doc files omitted by standard install
for f in COPYRIGHT CREDITS INSTALL README.rst; do
    cp $f $RPM_BUILD_ROOT/%{docdir}
done
cp LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.gpl
cp src/lib/LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.lgpl
cp src/LICENSE.openssl $RPM_BUILD_ROOT/%{docdir}/LICENSE.openssl

# add Red Hat specific documentation
cat >> $RPM_BUILD_ROOT/%{docdir}/REDHAT << EOF

Red Hat, RHEL, Fedora, and CentOS specific information can be found on the
FreeRADIUS Wiki in the Red Hat FAQ.

http://wiki.freeradius.org/guide/Red_Hat_FAQ

Please reference that document.

EOF


# Make sure our user/group is present prior to any package or subpackage installation
%pre
getent group  radiusd >/dev/null || /usr/sbin/groupadd -r -g 95 radiusd > /dev/null 2>&1
getent passwd radiusd >/dev/null || /usr/sbin/useradd  -r -g radiusd -u 95 -c "radiusd user" -s /sbin/nologin radiusd > /dev/null 2>&1
exit 0

%post
if [ $1 -eq 1 ]; then           # install
  /sbin/chkconfig --add radiusd
  if [ ! -e /etc/raddb/certs/server.pem ]; then
    /sbin/runuser -g radiusd -c 'umask 007; /etc/raddb/certs/bootstrap' > /dev/null 2>&1
  fi
fi
exit 0

%preun
if [ $1 -eq 0 ]; then           # uninstall
  /sbin/service radiusd stop > /dev/null 2>&1
  /sbin/chkconfig --del radiusd
fi
exit 0


%postun
if [ $1 -ge 1 ]; then           # upgrade
  /sbin/service radiusd condrestart >/dev/null 2>&1
fi
if [ $1 -eq 0 ]; then           # uninstall
  getent passwd radiusd >/dev/null && /usr/sbin/userdel  radiusd > /dev/null 2>&1
  getent group  radiusd >/dev/null && /usr/sbin/groupdel radiusd > /dev/null 2>&1
fi
exit 0

%files
%defattr(-,root,root)
%doc %{docdir}/
%config(noreplace) %{_sysconfdir}/pam.d/radiusd
%config(noreplace) %{_sysconfdir}/logrotate.d/radiusd
%{initddir}/radiusd
%dir %attr(710,radiusd,radiusd) %{_localstatedir}/run/radiusd
%dir %attr(755,radiusd,radiusd) %{_localstatedir}/lib/radiusd
# configs
%dir %attr(755,root,radiusd) /etc/raddb
%defattr(-,root,radiusd)
%attr(644,root,radiusd) %config(noreplace) /etc/raddb/dictionary
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%config(noreplace) /etc/raddb/attrs.access_challenge
%config(noreplace) /etc/raddb/attrs.access_reject
%config(noreplace) /etc/raddb/attrs.accounting_response
%config(noreplace) /etc/raddb/attrs.pre-proxy
%dir %attr(770,root,radiusd) /etc/raddb/certs
%attr(750,root,radiusd) /etc/raddb/certs/bootstrap
%config(noreplace) /etc/raddb/certs/Makefile
%config(noreplace) /etc/raddb/certs/README
%config(noreplace) /etc/raddb/certs/xpextensions
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/certs/*.cnf
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/clients.conf
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/eap.conf
%config(noreplace) %attr(640,root,radiusd) /etc/raddb/example.pl
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%dir %attr(750,root,radiusd) /etc/raddb/modules
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/modules/*
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/panic.gdb
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/policy.conf
%config(noreplace) /etc/raddb/policy.txt
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/preproxy_users
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/proxy.conf
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/radiusd.conf
%dir %attr(750,root,radiusd) /etc/raddb/sql
%dir %attr(750,root,radiusd) /etc/raddb/sql/*
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sql/*/*
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sql.conf
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sqlippool.conf
%dir %attr(750,root,radiusd) /etc/raddb/sites-available
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/*
%dir %attr(750,root,radiusd) /etc/raddb/sites-enabled
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-enabled/*
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/templates.conf
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/users
# binaries
%defattr(-,root,root)
/usr/sbin/*
# man-pages
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# dictionaries
%dir %attr(755,root,root) /usr/share/freeradius
/usr/share/freeradius/*
# logs
%dir %attr(700,radiusd,radiusd) /var/log/radius/
%dir %attr(700,radiusd,radiusd) /var/log/radius/radacct/
%ghost %attr(644,radiusd,radiusd) /var/log/radius/radutmp
%ghost %attr(600,radiusd,radiusd) /var/log/radius/radius.log
# RADIUS shared libs
%attr(755,root,root) %{_libdir}/freeradius/lib*.so*
# RADIUS Loadable Modules
%dir %attr(755,root,root) %{_libdir}/freeradius
%{_libdir}/freeradius/rlm_*.so

%files utils
/usr/bin/*
# man-pages
%doc %{_mandir}/man1/*

%files krb5

%files perl

%files python

%files mysql

%files postgresql

%files ldap

%files unixODBC

%changelog
* Thu May  9 2013 Fajar A. Nugraha <list@fajar.net> - 2.2.1-1
- bump version number to 2.2.1
- package everything in only two RPM: freeradius and freeradius-utils
- adapted spec file to be more generic

* Tue Apr 10 2012 John Dennis <jdennis@redhat.com> - 2.1.12-2
- resolves: bug#810605 Segfault with freeradius-perl threading
