ARG from=freeradius/centos7-deps
FROM ${from}

#
#  This is necessary for the jenkins server to talk to the docker instance
#
RUN yum install -y openssh-server java-1.8.0-openjdk-headless createrepo
RUN adduser jenkins
RUN printf jenkins1 | passwd --stdin jenkins
RUN mkdir /var/run/sshd

RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
