Summary: High-performance and highly configurable RADIUS server
URL: http://www.freeradius.org/
Name: freeradius-server
Version: 2.1.9
Release: 0
License: GPL
Group: Networking/Daemons
Packager: FreeRADIUS.org
Source0: %{name}-%{version}.tar.gz
Prereq: /sbin/chkconfig
BuildPreReq: libtool libtool-ltdl-devel
# FIXME: snmpwalk, snmpget and rusers POSSIBLY needed by checkrad
Provides: radiusd
Conflicts: cistron-radius
BuildRoot: %{_tmppath}/%{name}-root

%description
The FreeRADIUS Server Project is a high-performance and highly
configurable GPL'd RADIUS server. It is somewhat similar to the
Livingston 2.0 RADIUS server, but has many more features, and is much
more configurable.

%prep
%setup

%build
CFLAGS="$RPM_OPT_FLAGS" \
%configure --prefix=%{_prefix} \
	--localstatedir=%{_localstatedir} \
	--sysconfdir=%{_sysconfdir} \
	--mandir=%{_mandir} \
	--with-docdir=%{_datadir}/doc/%{name}-%{version} \
	--with-system-libtool \
	--disable-ltdl-install \
	--with-ltdl-lib=/usr/lib \
	--with-ltdl-include=/usr/include \
	--with-large-files --with-udpfromto --with-edir \
	--with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
	--with-rlm-krb5-include-dir=/usr/kerberos/include \
	--with-rlm-krb5-lib-dir=/usr/kerberos/lib
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/{logrotate.d,pam.d,rc.d/init.d}

make install R=$RPM_BUILD_ROOT

RADDB=$RPM_BUILD_ROOT/etc/raddb
# set radiusd as default user/group
perl -i -pe 's/^#user =.*$/user = radiusd/' $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
# shadow password file MUST be defined on Linux
perl -i -pe 's/#	shadow =/shadow =/' $RADDB/radiusd.conf

# remove unneeded stuff
rm -f $RPM_BUILD_ROOT%{_prefix}/sbin/rc.radiusd

# more files go to /usr/share/doc/freeradius-%{version}
install -m 0644 CREDITS $RPM_BUILD_ROOT%{_datadir}/doc/%{name}-%{version}
install -m 0644 COPYRIGHT $RPM_BUILD_ROOT%{_datadir}/doc/%{name}-%{version}
install -m 0644 LICENSE $RPM_BUILD_ROOT%{_datadir}/doc/%{name}-%{version}

cd redhat
install -m 755 rc.radiusd-redhat $RPM_BUILD_ROOT/etc/rc.d/init.d/radiusd
install -m 644 radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -m 644 radiusd-pam       $RPM_BUILD_ROOT/etc/pam.d/radius
cd ..

%pre
/usr/sbin/useradd -c "radiusd user" -r -s /bin/false -u 95 -d / radiusd 2>/dev/null || :

%preun
if [ "$1" = "0" ]; then
	/sbin/service radiusd stop > /dev/null 2>&1
	/sbin/chkconfig --del radiusd
fi

%post
/sbin/ldconfig
/sbin/chkconfig --add radiusd

# Done here to avoid messing up existing installations
for i in radius/radutmp radius/radwtmp radius/radius.log # radius/radwatch.log radius/checkrad.log
do
	touch /var/log/$i
	chown radiusd:radiusd /var/log/$i
	chmod 600 /var/log/$i
done

%postun
if [ "$1" -ge "1" ]; then
	/sbin/service radiusd condrestart >/dev/null 2>&1
fi
if [ $1 = 0 ]; then
	/usr/sbin/userdel radiusd > /dev/null 2>&1 || :
fi
/sbin/ldconfig

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config /etc/pam.d/radius
%config /etc/logrotate.d/radiusd
%config /etc/rc.d/init.d/radiusd
%config (noreplace) /etc/raddb/*
%doc %{_datadir}/doc/%{name}-%{version}
%{_bindir}/*
%{_datadir}/freeradius
%{_libdir}/*
%{_mandir}/*/*
%{_sbindir}/*
%{_includedir}/freeradius/*
%attr(0700,radiusd,radiusd) %dir /var/log/radius
%attr(0700,radiusd,radiusd) %dir /var/log/radius/radacct
%attr(0700,radiusd,radiusd) %dir /var/run/radiusd

%changelog
* Thu Dec 15 2004 Alan DeKok
- update for 1.1.0

* Mon May 31 2004 Paul Hampson
- update for 1.0.0 release

* Fri May 23 2003 Marko Myllynen
- update for 0.9

* Wed Sep  4 2002 Marko Myllynen
- fix libtool issues for good

* Thu Aug 22 2002 Marko Myllynen
- update for 0.7/0.8

* Tue Jun 18 2002 Marko Myllynen
- run as radiusd user instead of root
- added some options for configure

* Thu Jun  6 2002 Marko Myllynen
- set noreplace for non-dictionary files in /etc/raddb

* Sun May 26 2002 Frank Cusack <frank@google.com>
- move /var dirs from %%post to %%files

* Thu Feb 14 2002 Marko Myllynen
- use dir name macros in all configure options
- libtool is required only when building the package
- misc clean ups

* Wed Feb 13 2002 Marko Myllynen
- use %%{_mandir} instead of /usr/man
- rename %%postin as %%post
- clean up name/version

* Fri Jan 18 2002 Frank Cusack <frank@google.com>
- remove (noreplace) for /etc/raddb/* (due to rpm bugs)

* Fri Sep 07 2001 Ivan F. Martinez <ivanfm@ecodigit.com.br>
- changes to make compatible with default config file shipped
- adjusts log files are on /var/log/radius instead of /var/log
- /etc/raddb changed to config(noreplace) to don't override
-   user configs

* Fri Sep 22 2000 Bruno Lopes F. Cabral <bruno@openline.com.br>
- spec file clear accordling to the libltdl fix and minor updates

* Wed Sep 12 2000 Bruno Lopes F. Cabral <bruno@openline.com.br>
- Updated to snapshot-12-Sep-00

* Fri Jun 16 2000 Bruno Lopes F. Cabral <bruno@openline.com.br>
- Initial release
