FROM debian:wheezy
RUN apt-get update && apt-get install -y sudo firebird-dev freetds-dev libcap-dev libcollectdclient-dev libcurl4-openssl-dev libgdbm-dev libhiredis-dev libidn11-dev libiodbc2-dev libjson0-dev libldap2-dev libpq-dev libmemcached-dev libmysqlclient-dev libpam0g-dev libpcap-dev libperl-dev libsqlite3-dev libunbound-dev libtalloc-dev libwbclient-dev libykclient-dev libyubikey-dev python-dev ruby ruby-dev snmp software-properties-common python-software-properties libssl-dev libtalloc-dev libkqueue-dev make packaging-dev libkrb5-dev libreadline-dev samba4-dev openssh-server mercurial

RUN hg clone http://hg.openjdk.java.net/jdk8/jdk8 YourOpenJDK ;\
    cd YourOpenJDK ;\
    bash ./get_source.sh
RUN apt-get install -y cpio zip openjdk-7-jdk libX11-dev libxext-dev libxrender-dev libxtst-dev libxt-dev cups libcups2-dev
RUN apt-get install -y libfreetype6-dev libasound2-dev 
ENV DISABLE_HOTSPOT_OS_VERSION_CHECK=ok
RUN cd YourOpenJDK && bash ./configure && make 
RUN cd YourOpenJDK && make install
RUN echo "deb http://http.debian.net/debian wheezy-backports main" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y gcc-4.9 g++-4.9
#RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 50 --slave /usr/bin/g++ g++ /usr/bin/g++-4.9 && update-alternatives --config gcc
RUN apt-get install -y sudo && echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers
RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN mkdir /var/run/sshd
# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
