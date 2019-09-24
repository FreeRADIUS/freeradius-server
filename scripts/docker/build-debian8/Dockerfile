ARG from=debian:jessie
FROM ${from} as build

ARG gccver=4.9

#
#  Install build tools
#
RUN apt-get update
RUN apt-get install -y devscripts equivs git quilt g++-${gccver} rsync

#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories
WORKDIR /usr/local/src/repositories

#
#  Shallow clone the FreeRADIUS source
#
ARG source=https://github.com/FreeRADIUS/freeradius-server.git
ARG release=v3.0.x

RUN git clone --depth 1 --single-branch --branch ${release} ${source}
WORKDIR freeradius-server

#
#  Install build dependencies
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
COPY --from=build /usr/local/src/repositories/*.deb /tmp/

RUN apt-get update \
    && dpkg -i /tmp/*.deb || true \
    && apt-get -y -f install \
    && apt-get clean \
    && rm -r /var/lib/apt/lists/* /tmp/*.deb \
    \
    && ln -s /etc/freeradius /etc/raddb

COPY docker-entrypoint.sh /

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["freeradius"]
