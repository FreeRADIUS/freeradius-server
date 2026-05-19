#
#  Set up NetworkRADIUS extras repository. OS_NAME and OS_CODENAME are
#  substituted by the dispatcher (Dockerfile.m4) per-distro.
#
RUN install -d -o root -g root -m 0755 /etc/apt/keyrings && \
	curl --retry 3 --retry-delay 10 --retry-connrefused --fail \
		-o /etc/apt/keyrings/packages.networkradius.com.asc \
		"https://packages.networkradius.com/pgp/packages%40networkradius.com"

RUN echo "deb [signed-by=/etc/apt/keyrings/packages.networkradius.com.asc] http://packages.networkradius.com/extras/OS_NAME/OS_CODENAME OS_CODENAME main" \
		> /etc/apt/sources.list.d/networkradius-extras.list && \
	apt-get update
