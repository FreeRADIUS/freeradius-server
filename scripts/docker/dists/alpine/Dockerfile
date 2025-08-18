# Auto generated for alpine
# from scripts/docker/m4/Dockerfile.alpine.m4
#
# Rebuild this file with `make docker.alpine.regen`
#
ARG from=alpine:3.21
FROM ${from} AS build

#
#  Install build tools
#
RUN apk update
RUN apk add git gcc make

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
# essential
RUN apk add libc-dev talloc-dev
RUN apk add openssl openssl-dev
RUN apk add linux-headers
# general
RUN apk add pcre-dev libidn-dev krb5-dev samba-dev curl-dev json-c-dev
RUN apk add openldap-dev unbound-dev
# languages
RUN apk add ruby-dev perl-dev python3-dev
# databases
RUN apk add hiredis-dev libmemcached-dev gdbm-dev
# sql
RUN apk add postgresql-dev mariadb-dev unixodbc-dev sqlite-dev

#
#  Build the server
#
RUN ./configure --prefix=/opt
RUN make -j2
RUN make install
RUN rm /opt/lib/*.a

#
#  Clean environment and run the server
#
FROM ${from}
COPY --from=build /opt /opt

#
# These are needed for the server to start
#
RUN apk update \
    && apk add talloc libressl pcre libwbclient tzdata \
    \
#
#  Libraries that are needed dependent on which modules are used
#  Some of these (especially the languages) are huge. A reasonable
#  selection has been enabled here. If you use modules needing
#  other dependencies then install any others required in your
#  local Dockerfile.
#
    && apk add libcurl json-c libldap hiredis sqlite-dev \
#RUN apk add libidn krb5
#RUN apk add unbound-libs
#RUN apk add ruby-libs perl python3-dev
#RUN apk add libmemcached gdbm
#RUN apk add postgresql-dev mariadb-dev unixodbc-dev
    \
    && ln -s /opt/etc/raddb /etc/raddb

WORKDIR /
COPY scripts/docker//etc/docker-entrypoint.sh.alpine docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["radiusd"]
