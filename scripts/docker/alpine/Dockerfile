ARG from=alpine:latest
FROM ${from}

ARG release=v3.0.x
ARG source=https://github.com/FreeRADIUS/freeradius-server.git

#
#  We really need this stuff
#
RUN apk add --update git gcc make

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
# essential
RUN apk add libc-dev talloc-dev
RUN apk add libressl libressl-dev
RUN apk add linux-headers
# general
RUN apk add pcre-dev libidn-dev krb5-dev samba-dev curl-dev json-c-dev
RUN apk add openldap-dev unbound-dev
# languages
RUN apk add ruby-dev perl-dev python2-dev
# databases
RUN apk add hiredis-dev libmemcached-dev gdbm-dev libcouchbase-dev
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

COPY --from=0 /opt /opt

# needed for the server to start
RUN apk add --update talloc libressl pcre libwbclient

#
#  Libraries that are needed dependent on which modules are used
#  Some of these (especially the languages) are huge...
#
RUN apk add libcurl json-c
#RUN apk add libidn krb5
RUN apk add libldap
#RUN apk add unbound-libs
#RUN apk add ruby-libs perl python2
RUN apk add hiredis
#RUN apk add libmemcached gdbm libcouchbase
#RUN apk add postgresql-dev mariadb-dev unixodbc-dev sqlite-dev
RUN apk add sqlite-dev

EXPOSE 1812/udp 1813/udp
CMD ["/opt/sbin/radiusd", "-X"]
