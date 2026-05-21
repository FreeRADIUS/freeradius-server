ARG from=DOCKER_IMAGE
FROM ${from}

#
#  Install profiling tools
#
#    valgrind / cachegrind
#    kcachegrind + KDE/Qt runtime libs (cachegrind annotation viewer)
#    gperftools (libgoogle-perftools-dev ships the pprof binaries too,
#    so we don't need the separate google-perftools package -- which
#    has been retired from newer debian/ubuntu archives anyway)
#    heaptrack
#
RUN apt-get update && \
    apt-get install -y $APT_OPTS \
        libgoogle-perftools-dev \
        valgrind \
        heaptrack \
        psmisc \
        kcachegrind \
        kio \
        libkf5iconthemes5 \
        libkf5parts5 \
        libkf5textwidgets5 \
        libqt5gui5 \
        libqt5widgets5 && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*

include(`common.deb.dbgsym.m4')dnl

#
#  Install FlameGraph
#
RUN git clone --depth 1 https://github.com/brendangregg/FlameGraph /opt/flamegraph \
    && chmod +x /opt/flamegraph/*.pl /opt/flamegraph/*.sh

ENV PATH="/opt/flamegraph:${PATH}"

#
#  Install Inferno (Rust port of FlameGraph with broader format support).
#  Bootstrap rustup so we always have a recent stable toolchain --
#  debian12's distro cargo (1.63) is too old for current inferno's
#  transitive crate MSRVs, and pinning to an older inferno just defers
#  the same drift everywhere else. Uninstall the toolchain after the
#  build to keep the layer small.
#
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal && \
    . "$HOME/.cargo/env" && \
    cargo install inferno --version 0.11.21 --locked --root /usr/local && \
    rm -rf "$HOME/.cargo" "$HOME/.rustup"

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
