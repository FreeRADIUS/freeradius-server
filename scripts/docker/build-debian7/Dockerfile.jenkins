ARG from=freeradius/debian7-deps
FROM ${from}

ARG osname=wheezy

ARG DEBIAN_FRONTEND=noninteractive

#
#  This is necessary for the jenkins server to talk to the docker instance
#
ENV DISABLE_HOTSPOT_OS_VERSION_CHECK=ok

RUN hg clone http://hg.openjdk.java.net/jdk8/jdk8 YourOpenJDK ;\
    cd YourOpenJDK ;\
    bash ./get_source.sh
RUN apt-get install -y cpio zip openjdk-7-jdk libX11-dev libxext-dev libxrender-dev \
    libxtst-dev libxt-dev cups libcups2-dev libfreetype6-dev libasound2-dev

RUN cd YourOpenJDK && bash ./configure && make
RUN cd YourOpenJDK && make install

RUN apt-get install -y openssh-server sudo

RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers
RUN mkdir /var/run/sshd

# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
