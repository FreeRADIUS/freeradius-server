FROM freeradius/debian9-source

WORKDIR /usr/local/src/repositories/freeradius-server
RUN ./configure --prefix=/opt/freeradius
RUN make -j2
RUN make install
WORKDIR /opt/freeradius/etc/raddb
RUN sed -i -e 's/allow_vulnerable_openssl.*/allow_vulnerable_openssl = yes/' radiusd.conf
WORKDIR certs
RUN make
WORKDIR /

EXPOSE 1812/udp 1813/udp
CMD ["/opt/freeradius/sbin/radiusd", "-X"]

