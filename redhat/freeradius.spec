%define name freeradius-alpha-snapshot
# FIXME: find a way of getting rid of "-" on versions ... rpm will be happy
%define ver 22-Sep-00
%define verX 22_Sep_00

Name: %{name}
Version: %{verX}
Release: 0

Summary:	High-performance and highly configurable RADIUS server
URL:		http://www.freeradius.org/
Copyright:	GPL
Group:		Networking/Daemons

Prereq:		/sbin/chkconfig
# FIXME: snmpwalk, snmpget and rusers POSSIBLY needed by checkrad
Requires:	libtool
Conflicts:	cistron-radius

Source:		%{name}-%{ver}.tar.gz
# FIXME: won't be good to include these contrib examples?
# Source1:	http://www.ping.de/~fdc/radius/radacct-replay
# Source2:	http://www.ping.de/~fdc/radius/radlast-0.03
# Source3:	ftp://ftp.freeradius.org/pub/radius/contrib/radwho.cgi

%define setupdir %{name}-%{ver}
BuildRoot: /var/tmp/%{setupdir}.root

%description
The FreeRADIUS Server Project is an attempt to create a high-performance 
and highly configurable GPL'd RADIUS server. It is generally similar to 
the Livingston 2.0 RADIUS server, but has a lot more features, and is 
much more configurable.

%prep 
%setup -qn %{setupdir}

# FIXME: some folks prefer -dist files ... rename them or not?
#cd raddb
#chmod 640 clients naspasswd radiusd.conf.in
#cd ..

%build
CFLAGS="$RPM_OPT_FLAGS" \
%configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
	--mandir=/usr/man \
	--with-threads \
	--with-thread-pool \
	--with-gnu-ld \
	--disable-ltdl-install
make

%install
# prepare $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/{logrotate.d,pam.d,rc.d/init.d}

# install files
make install R=$RPM_BUILD_ROOT

# remove unneeded stuff
rm -f $RPM_BUILD_ROOT/usr/{man/man8/builddbm.8,sbin/rc.radiusd}

cd redhat
install -m 555 rc.radiusd-redhat $RPM_BUILD_ROOT/etc/rc.d/init.d/radiusd
install -m 644 radiusd-logrotate $RPM_BUILD_ROOT/etc/logrotate.d/radiusd
install -m 644 radiusd-pam       $RPM_BUILD_ROOT/etc/pam.d/radius
cd ..

%preun
if [ "$1" = "0" ]; then
	/sbin/chkconfig --del radiusd
fi

%postin
if [ "$1" = "0" ]; then
	/sbin/chkconfig --add radiusd
fi
if [ ! -d /var/log/radius ]; then
    mkdir -p /var/log/radius
fi
# done here to avoid messing up existing installations
for i in radius radius/radutmp radius/radwtmp # radius/radius.log radius/radwatch.log radius/checkrad.log
do
  touch /var/log/$i
  chown root.root /var/log/$i
done

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc doc/ChangeLog doc/README* todo/ COPYRIGHT INSTALL
%config /etc/pam.d/radius
%config /etc/logrotate.d/radiusd
%config /etc/rc.d/init.d/radiusd
%config(noreplace) /etc/raddb/*
/usr/man/*
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

