#
# spec file for package freeradius (Version 0.4)
#
# Copyright (c) 2002 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# please send bugfixes or comments to feedback@suse.de.
#

# neededforbuild  cyrus-sasl-devel heimdal-devel heimdal-lib mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel postgresql-devel postgresql-libs
# usedforbuild    aaa_base aaa_dir aaa_version autoconf automake base bash bindutil binutils bison bzip cpio cpp cracklib cyrus-sasl cyrus-sasl-devel db devs diffutils e2fsprogs file fileutils findutils flex gawk gcc gdbm gdbm-devel gettext glibc glibc-devel glibc-locale gpm gppshare grep groff gzip heimdal-devel heimdal-lib kbd less libtool libz m4 make man mktemp modutils mysql-devel mysql-shared ncurses ncurses-devel net-tools netcfg openldap2 openldap2-client openldap2-devel openssl openssl-devel pam pam-devel pam-modules patch perl postgresql-devel postgresql-libs ps rcs readline rpm sendmail sh-utils shadow strace syslogd sysvinit texinfo textutils timezone unzip util-linux vim

Name:         freeradius
Copyright:    GPL
Group:        Productivity/Networking/Radius/Servers
Provides:     radiusd
Conflicts:    radiusd-livingston radiusd-cistron icradius
Version:      0.4
Release:      129
URL:          http://www.freeradius.org/
Summary:      Very high configurable Radius-server (BETA)
Source0:      %{name}-%{version}.tar.bz2
Source1:      rcradiusd
Source2:      radiusd-pam
Patch:        heimdal.dif
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

SuSE series: n

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

SuSE series: n

%prep
%setup -n radiusd
%patch
%{?suse_update_config:%{suse_update_config}}

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure \
		--prefix=/ \
		--exec_prefix=/usr \
                --sysconfdir=%{_sysconfdir} \
		--infodir=%{_infodir} \
		--mandir=%{_mandir} \
		--with-rlm-krb5-include-dir=/usr/include/heimdal/ \
		--with-rlm-krb5-lib-dir=/usr/lib/
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf \
$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install R=$RPM_BUILD_ROOT
ldconfig -n $RPM_BUILD_ROOT%{prefix}/lib
# logs
touch $RPM_BUILD_ROOT/var/log/radius/radius.log
touch $RPM_BUILD_ROOT/var/log/radius/radwatch.log
touch $RPM_BUILD_ROOT/var/log/radius/radwtmp
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
# SuSE
install -d     $RPM_BUILD_ROOT/etc/pam.d
install -m 644 %SOURCE2 $RPM_BUILD_ROOT/etc/pam.d/radiusd
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install    -m 744 %SOURCE1 $RPM_BUILD_ROOT/etc/init.d/radiusd
ln -sf ../../etc/init.d/radiusd $RPM_BUILD_ROOT/usr/sbin/rcradiusd

%post
%{fillup_and_insserv -s radiusd START_RADIUSD }

%postun
%{insserv_cleanup}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT

%files
# doc
%doc doc/* LICENSE COPYRIGHT CREDITS README
# SuSE
%config /etc/init.d/radiusd
%config /etc/pam.d/radiusd
/usr/sbin/rcradiusd
# configs
%dir /etc/raddb
%config(noreplace) /etc/raddb/acct_users
%config(noreplace) /etc/raddb/attrs
%config(noreplace) /etc/raddb/clients
%config(noreplace) /etc/raddb/clients.conf
%config /etc/raddb/dictionary
%config /etc/raddb/dictionary.acc
%config /etc/raddb/dictionary.ascend
%config /etc/raddb/dictionary.bay
%config /etc/raddb/dictionary.cisco
%config /etc/raddb/dictionary.compat
%config /etc/raddb/dictionary.erx
%config /etc/raddb/dictionary.freeradius
%config /etc/raddb/dictionary.livingston
%config /etc/raddb/dictionary.microsoft
%config /etc/raddb/dictionary.nomadix
%config /etc/raddb/dictionary.redback
%config /etc/raddb/dictionary.shasta
%config /etc/raddb/dictionary.shiva
%config /etc/raddb/dictionary.tunnel
%config /etc/raddb/dictionary.usr
%config /etc/raddb/dictionary.versanet
%config(noreplace) /etc/raddb/hints
%config(noreplace) /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/ldap.attrmap
%config(noreplace) /etc/raddb/naslist
%config(noreplace) /etc/raddb/naspasswd
%config(noreplace) /etc/raddb/proxy.conf
%config(noreplace) /etc/raddb/radiusd.conf
%config(noreplace) /etc/raddb/realms
%config(noreplace) /etc/raddb/snmp.conf
%config(noreplace) /etc/raddb/sql.conf
%config(noreplace) /etc/raddb/users
%config(noreplace) /etc/raddb/x99.conf
%config(noreplace) /etc/raddb/x99passwd.sample
# binaries
/usr/bin/*
/usr/sbin/check-radiusd-config
/usr/sbin/checkrad
/usr/sbin/radiusd
/usr/sbin/radwatch
# shared libs
/usr/lib/*.so.*
/usr/lib/*.la
# man-pages
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
# logs
%dir /var/log/radius/
%dir /var/log/radius/radacct/
/var/log/radius/radutmp
%ghost /var/log/radius/radwtmp
%ghost /var/log/radius/radius.log
%ghost /var/log/radius/radwatch.log

%files devel
/usr/lib/*.a
/usr/lib/*.so

%changelog -n freeradius
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
