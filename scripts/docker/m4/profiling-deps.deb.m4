ARG from=DOCKER_IMAGE

#
#  Build the Go pprof (github.com/google/pprof), which writes the
#  `pprof -proto` output the profiling server ingests.
#  Using pprof commit hash since there's no release tag available.
#
FROM golang:1.27 AS pprof
ARG PPROF_COMMIT=d6c3cb2f37ec22719bbaf5eb031d9a46635cb5b2
RUN CGO_ENABLED=0 GOBIN=/out go install "github.com/google/pprof@${PPROF_COMMIT}"

FROM ${from}

#
#  Install profiling tools
#
#    valgrind / cachegrind
#    kcachegrind + KDE/Qt runtime libs (cachegrind annotation viewer)
#    gperftools (`libgoogle-perftools-dev` provides libprofiler)
#    pprof (Go pprof)
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

COPY --from=pprof /out/pprof /usr/local/bin/pprof

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
