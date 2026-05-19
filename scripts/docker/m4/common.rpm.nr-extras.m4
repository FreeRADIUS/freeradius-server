changequote([{,}])dnl
#
#  Set up NetworkRADIUS extras repository. OS_NAME is substituted by the
#  dispatcher (Dockerfile.m4); $releasever resolves at dnf runtime so the
#  same repo file works on rocky9 and rocky10.
#
RUN curl --retry 3 --retry-delay 10 --retry-connrefused --fail \
        -o /etc/pki/rpm-gpg/packages.networkradius.com.asc \
        "https://packages.networkradius.com/pgp/packages%40networkradius.com"

RUN echo $'[networkradius-extras]\n\
name=NetworkRADIUS-extras-$releasever\n\
baseurl=http://packages.networkradius.com/extras/OS_NAME/$releasever/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/packages.networkradius.com.asc'\
> /etc/yum.repos.d/networkradius-extras.repo
RUN rpm --import /etc/pki/rpm-gpg/packages.networkradius.com.asc
changequote(`,')dnl
