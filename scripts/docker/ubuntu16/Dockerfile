ARG from=ubuntu:16.04
FROM ${from}

ARG source=https://github.com/FreeRADIUS/freeradius-server.git
ARG release=v3.0.x


#
#  Install build deps
#
RUN apt-get update && \
    apt-get install -y devscripts equivs git quilt gcc


#
#  Setup a src dir in /usr/local
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories


#
#  Shallow clone the FreeRADIUS source
#
RUN git clone --depth 1 --single-branch --branch ${release} ${source}
WORKDIR freeradius-server


#
#  Install build dependencies for v3.0.x
#
RUN git checkout ${release}; \
    if [ -e ./debian/control.in ]; then \
        debian/rules debian/control; \
    fi; \
    echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control


#
#  Build the server
#
RUN make -j2 deb


#
#  Clean environment and run the server
#
FROM ${from}
COPY --from=0 /usr/local/src/repositories/*.deb /tmp/

RUN apt-get update && \
    dpkg -i /tmp/*.deb || true && \
    apt-get -y -f install && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/* /tmp/*.deb

EXPOSE 1812/udp 1813/udp
CMD ["/usr/sbin/freeradius", "-X"]
