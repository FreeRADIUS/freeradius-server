ARG from=freeradius/ubuntu14-deps
FROM ${from}

ARG osname=trusty

ARG DEBIAN_FRONTEND=noninteractive

#
#  This is necessary for the jenkins server to talk to the docker instance
#
RUN apt-add-repository ppa:openjdk-r/ppa
RUN apt-get update && apt-get install -y openjdk-8-jre-headless

RUN apt-get install -y openssh-server sudo

RUN useradd -m jenkins
RUN echo "jenkins:jenkins1" | chpasswd
RUN echo "jenkins ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers
RUN mkdir /var/run/sshd

# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
