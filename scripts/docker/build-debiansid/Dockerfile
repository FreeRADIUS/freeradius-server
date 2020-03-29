ARG from=freeradius/debiansid-deps
FROM ${from}

SHELL ["/usr/bin/nice", "-n", "5", "/usr/bin/ionice", "-c", "3", "/bin/sh", "-x", "-c"]

ARG from=freeradius/debiansid-deps

ARG cc=gcc
ARG branch=master

WORKDIR /usr/local/src/repositories/freeradius-server
RUN git checkout ${branch}
RUN CC=${cc} ./configure --prefix=/opt/freeradius
RUN make -j$(($(getconf _NPROCESSORS_ONLN) + 1))
RUN make install
WORKDIR /opt/freeradius/etc/raddb
RUN sed -i -e 's/allow_vulnerable_openssl.*/allow_vulnerable_openssl = yes/' radiusd.conf
WORKDIR certs
RUN make
WORKDIR /

FROM ${from}
COPY --from=0 /opt/freeradius /opt/freeradius

EXPOSE 1812/udp 1813/udp
CMD ["/opt/freeradius/sbin/radiusd", "-X"]
