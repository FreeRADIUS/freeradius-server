FROM debian:jessie

#
# Jessie has now been archived, so we need to remove the updates
# line from sources.list
#
RUN sed -i '/jessie-updates/d' /etc/apt/sources.list  
#
#  Install build tools
#
RUN apt-get update
RUN apt-get install -y devscripts equivs git quilt g++-${gccver}

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

