Summary: Cistron RADIUS daemon (with PAM) 
Summary(pt_BR): Servidor RADIUS com muitas funcoes.
Name: radiusd-cistron
Version: 1.5.4.3
Release: beta19
Source: radiusd-cistron-1.5.4.3-beta19.tar.gz
URL: http://www.miquels.cistron.nl/radius/
Copyright: GPL
Group: Networking/Daemons
BuildRoot: /usr/tmp/radiusd

%description
RADIUS server with a lot of functions. Short overview: 

- PAM support
- Supports access based on huntgroups
- Multiple DEFAULT entries in users file
- All users file entries can optionally "fall through"
- Caches all config files in-memory
- Keeps a list of logged in users (radutmp file)
- "radwho" program can be installed as "fingerd"
- Logs both UNIX "wtmp" file format and RADIUS detail logfiles
- Supports Simultaneous-Use = X parameter. Yes, this means
  that you can now prevent double logins!

%description -l pt_BR
Servidor RADIUS com muitas funções. Visão geral:

- Suporta acesso baseado em huntgroups
- Multiplas entradas DEFAULT no arquivo de usuarios
- Faz cache de todos os arquivos de configuracão em memoria
- Mantem uma lista dos usuarios conectados (arquivo radutmp)
- O programa radwho pode ser instalado como fingerd
- Registra tanto no formato UNIX wtmp quanto no RADIUS detail
- Suporta o parametro Simultaneous-Use = X. Sim, isto significa
  que você pode evitar logins duplos!, inclusive com o Cyclades PathRas

%changelog
* Sat Nov 21 1998 Tim Hockin <thockin@ais.net>
- Based on work by Christopher McCrory <chrismcc@netus.com>
- Build with PAM
- Included pam.d/radius
- Fixed some small errors in this spec
- Changed to build to BuildRoot
- Changed Release to "beta11" from "1"
- Included users, naslist, huntgroups, clients files, not just -dist

* Tue Oct 27 1998 Mauricio Mello de Andrade <mandrade@mma.com.br>
- Corrected the script to Start/Stop the Radius under RH5.x
- Included the script to Rotate Radius Logs under RedHat
- Checkrad Utility now works fine with Cyclades PathRas

%prep 
%setup
cd raddb
for f in clients users naslist huntgroups ; do cp $f $f-dist ; done
cd ..

%build
./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --with-pam
make

%install
# prepare $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT/{,etc/{,raddb,logrotate.d,pam.d,rc.d/{,init.d,rc{0,1,2,3,4,5,6}.d}},usr/{,bin,sbin,man/{,man{1,5,8}}},var/{,log/{,radacct}}}

# make install
make install ROOT=${RPM_BUILD_ROOT}
install -m 755 src/radtest ${RPM_BUILD_ROOT}/usr/bin/
cd ..

# do /etc/raddb
cd raddb
install -m 640 * ${RPM_BUILD_ROOT}/etc/raddb
cd ..

# radwatch
install -m 755 scripts/radwatch ${RPM_BUILD_ROOT}/usr/sbin/

# other files
cd redhat
install -m 555 rc.radiusd-redhat ${RPM_BUILD_ROOT}/etc/rc.d/init.d/radiusd.init
install -m 644 radiusd-logrotate ${RPM_BUILD_ROOT}/etc/logrotate.d/radiusd
install -m 644 radiusd-pam ${RPM_BUILD_ROOT}/etc/pam.d/radius
cd ..

# man pages
cd doc
for i in 1 8; do
	install -m 444 *.$i ${RPM_BUILD_ROOT}/usr/man/man$i
done
install -m 444 clients.5rad ${RPM_BUILD_ROOT}/usr/man/man5/
install -m 444 naslist.5rad ${RPM_BUILD_ROOT}/usr/man/man5/
cd ..

# rc.d files
for i in 3 4 5;  do
	ln -sf ../init.d/radiusd.init ${RPM_BUILD_ROOT}/etc/rc.d/rc$i.d/S88radiusd.init
done
for i in 0 1 2 6; do
	ln -sf ../init.d/radiusd.init ${RPM_BUILD_ROOT}/etc/rc.d/rc$i.d/K12radiusd.init
done

for i in radutmp radwtmp radius.log; do
	touch ${RPM_BUILD_ROOT}/var/log/$i
	chown root.root ${RPM_BUILD_ROOT}/var/log/$i
	mkdir -p /var/log/radacct
done

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc doc/ChangeLog doc/README doc/README.pam doc/README.proxy 
%doc doc/README.usersfile doc/README.simul doc/INSTALL.OLD 
%doc doc/Makefile.README doc/README.cisco todo/ 
%doc COPYRIGHT.Cistron COPYRIGHT.Livingston

/usr/bin/*
/usr/sbin/*
/usr/man/man1/*
/usr/man/man5/*
/usr/man/man8/*
/var/log/radutmp
/var/log/radwtmp
/var/log/radius.log
%dir /var/log/radacct/

%dir /etc/raddb/
%config /etc/raddb/*
%config /etc/pam.d/radius
%config /etc/logrotate.d/radiusd
%config /etc/rc.d/init.d/radiusd.init
%config(missingok) /etc/rc.d/rc0.d/K12radiusd.init
%config(missingok) /etc/rc.d/rc1.d/K12radiusd.init
%config(missingok) /etc/rc.d/rc2.d/K12radiusd.init
%config(missingok) /etc/rc.d/rc3.d/S88radiusd.init
%config(missingok) /etc/rc.d/rc4.d/S88radiusd.init
%config(missingok) /etc/rc.d/rc5.d/S88radiusd.init
%config(missingok) /etc/rc.d/rc6.d/K12radiusd.init
