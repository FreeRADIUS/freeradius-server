ARG from=freeradius/debian10-deps
FROM ${from}

ARG cc=gcc

WORKDIR /usr/local/src/repositories/freeradius-server
RUN git checkout master; git pull
RUN CC=${cc} ./configure --prefix=/opt/freeradius
RUN make -j2
RUN make install
WORKDIR /opt/freeradius/etc/raddb
RUN sed -i -e 's/allow_vulnerable_openssl.*/allow_vulnerable_openssl = yes/' radiusd.conf; \
    cd certs; \
    make;

#FROM ${from}
#COPY --from=0 /opt/freeradius /opt/freeradius

EXPOSE 1812/udp 1813/udp
CMD ["/opt/freeradius/sbin/radiusd", "-X"]

# We get the following error:
# https://github.com/FreeRADIUS/freeradius-server/blob/46311cad437ddd1d4e47d63863297447f2d77a0b/src/lib/tls/base.c#L558
RUN /opt/freeradius/sbin/radiusd -XC

