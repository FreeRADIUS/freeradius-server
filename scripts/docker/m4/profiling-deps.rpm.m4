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
#    kcachegrind
#    gperftools (the gperftools packages provide libprofiler)
#    pprof (Go pprof)
#    heaptrack
#
#  EPEL is enabled by common.rpm.toolchain.m4 in the crossbuild base
#  along with CRB; heaptrack / gperftools / kcachegrind all live there.
#  libkqueue itself was built from source in the toolchain layer via
#  common.rpm.libkqueue.m4, so we don't repeat it here.
#
RUN dnf install -y --skip-broken \
        gperftools-devel \
        gperftools \
        valgrind \
        heaptrack \
        psmisc \
        kcachegrind && \
    dnf clean all

include(`common.rpm.debuginfo.m4')dnl

#
#  Install FlameGraph
#
RUN git clone --depth 1 https://github.com/brendangregg/FlameGraph /opt/flamegraph \
    && chmod +x /opt/flamegraph/*.pl /opt/flamegraph/*.sh

ENV PATH="/opt/flamegraph:${PATH}"

#
#  Install Inferno (Rust port of FlameGraph with broader format support).
#  Bootstrap rustup so we always have a recent stable toolchain --
#  Rocky's distro cargo lags inferno's transitive crate MSRVs. Uninstall
#  the toolchain after the build to keep the layer small.
#
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal && \
    . "$HOME/.cargo/env" && \
    cargo install inferno --version 0.11.21 --locked --root /usr/local && \
    rm -rf "$HOME/.cargo" "$HOME/.rustup"

COPY --from=pprof /out/pprof /usr/local/bin/pprof

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
