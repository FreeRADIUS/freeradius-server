Summary: High-performance and highly configurable RADIUS server
URL: http://www.freeradius.org/
Name: freeradius
Version: 0.5
Release: 1
License: GPL
Group: Networking/Daemons
Packager: FreeRADIUS.org
Source0: %{name}-%{version}.tar.gz
# FIXME: won't be good to include these contrib examples?
# Source1: http://www.ping.de/~fdc/radius/radacct-replay
# Source2: http://www.ping.de/~fdc/radius/radlast-0.03
# Source3: ftp://ftp.freeradius.org/pub/radius/contrib/radwho.cgi
Prereq: /sbin/chkconfig
BuildPreReq: libtool
# FIXME: snmpwalk, snmpget and rusers POSSIBLY needed by checkrad
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
	--with-threads \
	--with-thread-pool \
	--with-gnu-ld \
	--disable-ltdl-install
make

%install
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/{logrotate.d,pam.d,rc.d/init.d}

make install R=$RPM_BUILD_ROOT

# remove unneeded stuff
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/builddbm.8
rm -f $RPM_BUILD_ROOT%{_prefix}/sbin/rc.radiusd

cd redhat
install -m 755 rc.radiusd-redhat $RPM_BUILD_ROOT/etc/rc.d/init.d/radiusd
install -m 644 radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -m 644 radiusd-pam       $RPM_BUILD_ROOT/etc/pam.d/radius
cd ..

%preun
if [ "$1" = "0" ]; then
	/sbin/chkconfig --del radiusd
fi

%post
if [ "$1" = "0" ]; then
	/sbin/chkconfig --add radiusd
fi

mkdir -p /var/log/radius/radacct
chmod 700 /var/log/radius
chmod 700 /var/log/radius/radacct
chown root:root /var/log/radius
chown root:root /var/log/radius/radacct

# Done here to avoid messing up existing installations
for i in radius/radutmp radius/radwtmp # radius/radius.log radius/radwatch.log radius/checkrad.log
do
  touch /var/log/$i
  chown root:root /var/log/$i
  chmod 600 /var/log/$i
done

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc doc/ChangeLog doc/README* todo/ COPYRIGHT INSTALL
%config /etc/pam.d/radius
%config /etc/logrotate.d/radiusd
%config /etc/rc.d/init.d/radiusd
%config /etc/raddb/*
%{_mandir}/*/*
/usr/bin/*
/usr/sbin/*
/usr/lib/*
#%dir(missingok) /var/log/radius/radacct/
#/var/log/radius/checkrad.log
#/var/log/radius/radwatch.log
#/var/log/radius/radius.log
#/var/log/radius/radwtmp
#/var/log/radius/radutmp

%changelog
* Thu Feb 14 2002 Marko Myllynen
- use dir name macros in all configure options
- libtool is required only when building the package
- misc clean ups

* Wed Feb 13 2002 Marko Myllynen
- use %{_mandir} instead of /usr/man
- rename %postin as %post
- clean up name/version

* Fri Jan 18 2002 Frank Cusack <frank@google.com>
- remove (noreplace) for /etc/raddb/*

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
