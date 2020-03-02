ARG from=freeradius/alpine-deps
FROM ${from}

#
#  Build the server
#
WORKDIR /usr/local/src/repositories
RUN ./configure --prefix=/opt
RUN make -j2
RUN make install
RUN rm /opt/lib/*.a

#
#  Clean environment and run the server
#
COPY --from=0 /opt /opt

#
# These are needed for the server to start
#
RUN apk update \
    && apk add talloc libressl pcre libwbclient \
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
#RUN apk add ruby-libs perl python2-dev
#RUN apk add libmemcached gdbm libcouchbase
#RUN apk add postgresql-dev mariadb-dev unixodbc-dev
    \
    && ln -s /opt/etc/raddb /etc/raddb

COPY docker-entrypoint.sh /

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["radiusd"]
