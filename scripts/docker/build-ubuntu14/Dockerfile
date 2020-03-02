ARG from=freeradius/ubuntu14-deps
FROM ${from}

#
#  Clean environment and run the server
#
COPY --from=0 /usr/local/src/repositories/*.deb /tmp/

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
