#
# spec file for package freeradius (Version 0.8)
#
# Copyright (c) 2002 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# please send bugfixes or comments to feedback@suse.de.
#

# neededforbuild  cyrus-sasl-devel heimdal-devel heimdal-lib mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel postgresql postgresql-devel postgresql-libs python python-devel unixODBC unixODBC-devel
# usedforbuild    aaa_base aaa_version acl attr bash bind9-utils bison cpio cpp cyrus-sasl db devs diffutils e2fsprogs file filesystem fileutils fillup findutils flex gawk gdbm-devel glibc glibc-devel glibc-locale gpm grep groff gzip kbd less libgcc libstdc++ libxcrypt m4 make man mktemp modutils ncurses ncurses-devel net-tools netcfg pam pam-devel pam-modules patch permissions ps rcs readline sed sendmail sh-utils shadow strace syslogd sysvinit tar texinfo textutils timezone unzip util-linux vim zlib-devel autoconf automake binutils bzip2 cracklib cyrus-sasl-devel gcc gdbm gettext heimdal-devel heimdal-lib libtool mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel perl postgresql postgresql-devel postgresql-libs python python-devel rpm unixODBC unixODBC-devel zlib

Name:         freeradius
License:      GPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    radiusd-livingston radiusd-cistron icradius
Version:      0.8pre
Release:      3
URL:          http://www.freeradius.org/
Summary:      Very high configurable Radius-server
#Source0:      %{name}-%{version}.tar.bz2
Source0:      freeradius-snapshot-20021105.tar.gz
Source1:      rcradiusd
Source2:      radiusd-pam
Source3:      radiusd-logrotate
#Patch:        krb5-configure.dif
#Patch1:       ltconfig.dif
#PreReq is needed for SuSE 8.1
#PreReq:       %insserv_prereq %fillup_prereq
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
        

%description
The FreeRADIUS server has a number of features which are found in other
servers, and additional features which are not found in any other server.
Rather than doing a feature by feature comparison, we will simply list
the features of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes
Additional server configuration attributes
Selecting a particular configuration
Authentication methods
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
%setup -n freeradius-snapshot-20021105
#%patch
#%patch1
# patch for heimdal
#(cd src/modules/rlm_krb5; patch -p0 < heimdal-krb5.patch)
#(cd src/modules/rlm_krb5; autoconf -l ../../../)

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure \
		--prefix=%{_prefix} \
                --sysconfdir=%{_sysconfdir} \
		--infodir=%{_infodir} \
		--mandir=%{_mandir} \
                --libdir=%{_libdir} \
		--localstatedir=/var \
		--with-threads \
		--with-thread-pool \
		--with-system-libtool \
		--disable-ltdl-install \
		--with-ltdl-lib=/usr/lib \
		--with-ltdl-include=/usr/include \
		--with-gnu-ld \
                --with-rlm-sql-postgresql-include-dir=/usr/include/pgsql/ \
		--without-rlm-krb5
#		--with-rlm-krb5-include-dir=/usr/include/heimdal/ \
#		--with-rlm-krb5-lib-dir=%{_libdir} \

make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf \
$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install R=$RPM_BUILD_ROOT
ldconfig -n $RPM_BUILD_ROOT%{_libdir}
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radius.log
touch $RPM_BUILD_ROOT/var/log/radius/radwatch.log
touch $RPM_BUILD_ROOT/var/log/radius/radwtmp
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
# SuSE
install -d     $RPM_BUILD_ROOT/etc/pam.d
install -d     $RPM_BUILD_ROOT/etc/logrotate.d
install -m 644 %SOURCE2 $RPM_BUILD_ROOT/etc/pam.d/radiusd
install -m 644 %SOURCE3 $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install    -m 744 %SOURCE1 $RPM_BUILD_ROOT/etc/init.d/radiusd
ln -sf ../../etc/init.d/radiusd $RPM_BUILD_ROOT/usr/sbin/rcradiusd
mv -v doc/README doc/README.doc

%post
%{fillup_and_insserv -s radiusd START_RADIUSD }

%postun
%{insserv_cleanup}

#%clean
#[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT

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
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%attr(640,root,root) %config(noreplace) /etc/raddb/clients
%attr(640,root,root) %config(noreplace) /etc/raddb/clients.conf
%config /etc/raddb/diction*
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%attr(640,root,root) %config(noreplace) /etc/raddb/mssql.conf
%config(noreplace) /etc/raddb/naslist
%attr(640,root,root) %config(noreplace) /etc/raddb/naspasswd
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
# binaries
/usr/bin/*
/usr/sbin/check-radiusd-config
/usr/sbin/checkrad
/usr/sbin/radiusd
/usr/sbin/radwatch
# shared libs
/%{_libdir}/*.so*
/%{_libdir}/*.la*
# man-pages
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# PID File
%attr(700,root,root) %dir /var/run/radiusd/
# logs
%attr(700,root,root) %dir /var/log/radius/
%attr(700,root,root) %dir /var/log/radius/radacct/
/var/log/radius/radutmp
%ghost /var/log/radius/radwtmp
%ghost /var/log/radius/radius.log
%ghost /var/log/radius/radwatch.log

%files devel
/%{_libdir}/*.a

%changelog -n freeradius
* Wed Nov 6 2002 - nix@susesecurity.com
- Finally got modules working on SuSE 8.0
- added /var/run/radiusd to spec file
* Mon Nov 4 2002 - nix@susesecurity.com
- Received this spec file from stark@suse.de who said he had managed to hack it
  enough to get a working FreeRadius0.8pre
- After commenting out some SuSE 8.1 specific and PPC specific stuff I managed
  to get it to build on SuSE 8.0
- Modules still don't work
* Mon Aug 19 2002 - ro@suse.de
- don't overwrite README's with each other
* Fri Aug 16 2002 - stark@suse.de
- added PreReq (Bug #17838)
* Thu Jun 20 2002 - ro@suse.de
- hack ltconfig for ppc64
* Mon Apr 08 2002 - stark@suse.de
- fixed packaging on 64bit platforms
- added logrotate config
- added some sample scripts to doc-dir
* Fri Mar 22 2002 - stark@suse.de
- update to 0.5
  * MS-CHAP and MS-CHAPv2 MPPE support,
  * EAP/MD5 and experimental EAP/TLS,
  * Experimental PHP web administration interface,
  * Fixes for *BSD,
  * Configurable database queries, executed per packet
  (e.g. %%{ldap:ldap:///dc=company,dc=com?uid?sub?uid=%%u}),
  * Fix logic bug which would cause occasional server crashes,
  * Server-side quenching of DoS attacks,
  * Experimental Python module,
  * Aptis, Quintum, and Foundry dictionaries,
  * Limited support for IPv6.
* Mon Feb 25 2002 - stark@suse.de
- moved *.la back to main-package as it is needed for
  dynamic loading of modules
* Mon Feb 25 2002 - stark@suse.de
- added patch to work with heimdal-krb5
- moved *.so to -devel package
* Fri Feb 08 2002 - stark@suse.de
- deactivated kerberos support
  (seems to be not compatible with heimdal :-()
* Thu Feb 07 2002 - stark@suse.de
- changed heimdal libdir
* Thu Dec 13 2001 - stark@suse.de
- update to 0.4
- better use of fillup_and_insserv
* Mon Dec 03 2001 - stark@suse.de
- don't use START_RADIUSD anymore
- make use of new fillup_and_insserv macro
* Fri Oct 12 2001 - stark@suse.de
- update to version 0.3
- packed source-archive as bz2
- branched package -> devel
* Fri Aug 03 2001 - stark@suse.de
- removed use of watcher-script
- removed config-check (-C) in init script
  (it's not supported in freeradius)
* Thu Aug 02 2001 - stark@suse.de
- status fix in init script
- renamed pam-configfile: radius -> radiusd
* Wed Aug 01 2001 - stark@suse.de
- updated to 0.2
* Thu Jul 26 2001 - kukuk@suse.de
- Fix needed for build
* Tue Jul 10 2001 - stark@suse.de
- added %%{suse_update_config}
* Sat Jun 23 2001 - schwab@suse.de
- Fix preprocessor directives inside macro arguments.
* Mon Jun 18 2001 - stark@suse.de
- removed absolute paths from pam-config
* Wed May 23 2001 - stark@suse.de
- first official beta-version 0.1
* Wed Mar 21 2001 - stark@suse.de
- new snapshot 20010321 (pre-BETA)
- replaced start- and killproc to avoid problems with Kernel 2.4
  using the radwatch shell-script
- added built of LDAP and MySQL modules
* Mon Jan 29 2001 - stark@suse.de
- %%files: /etc/raddb/bay.vendor -> /etc/raddb/dictionary.bay
* Mon Jan 15 2001 - stark@suse.de
- new snapshot 20010115
- initial BETA package (sources are ALPHA!)
* Thu Jan 04 2001 - stark@suse.de
- CVS snapshot 20010104
