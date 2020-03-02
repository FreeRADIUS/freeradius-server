ARG from=freeradius/ubuntu18-deps
FROM ${from}

#
#  Clean environment and run the server
#
COPY --from=0 /usr/local/src/repositories/*.deb /tmp/

RUN apt-get update \
    && apt-get install -y /tmp/*.deb \
    && apt-get clean \
    && rm -r /var/lib/apt/lists/* /tmp/*.deb \
    \
    && ln -s /etc/freeradius /etc/raddb

COPY docker-entrypoint.sh /

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["freeradius"]
