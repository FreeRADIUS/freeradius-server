# Auto generated for ubuntu20
# from scripts/docker/m4/Dockerfile.deb.m4
#
# Rebuild this file with `make docker.ubuntu20.regen`
#
ARG from=ubuntu:20.04
FROM ${from} as build

ARG DEBIAN_FRONTEND=noninteractive

#
#  Install build tools
#
RUN apt-get update
RUN apt-get install -y devscripts equivs git quilt gcc

#
#  Create build directory
#
RUN mkdir -p /usr/local/src/repositories/freeradius-server
WORKDIR /usr/local/src/repositories/freeradius-server/

#
#  Copy the FreeRADIUS directory in
#
COPY . .

#
#  Clean up tree - we want to build from the latest commit, not from
#  any cruft left around on the local system
#
RUN git clean -fdxx \
 && git reset --hard HEAD

ARG release
RUN [ -z "$release" ] || git checkout ${release} ; \
    git status ; \
    git log -1 --oneline

#
#  Install build dependencies
#
RUN if [ -e ./debian/control.in ]; then \
        debian/rules debian/control; \
    fi; \
    echo 'y' | mk-build-deps -irt'apt-get -yV' debian/control

#
#  Build the server
#
#  Work around fakeroot problems in Docker when building for different
#  platforms - doesn't matter as we run as root in the container anyway.
#
#RUN make -j$(nproc) deb
RUN debian/rules debian/control \
 && dpkg-buildpackage --jobs=auto -b -uc

#
#  Clean environment and run the server
#
FROM ${from}
ARG DEBIAN_FRONTEND=noninteractive

COPY --from=build /usr/local/src/repositories/*.deb /tmp/

RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN apt-get update \
 && apt-get install -y tzdata \
 && apt-get install -y /tmp/*.deb \
 && apt-get clean \
 && rm -r /var/lib/apt/lists/* /tmp/*.deb \
    \
 && ln -s /etc/freeradius /etc/raddb

WORKDIR /
COPY scripts/docker/etc/docker-entrypoint.sh.deb docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["freeradius"]
