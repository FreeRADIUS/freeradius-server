ARG from=DOCKER_IMAGE
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

#
#  Install the Go pprof (github.com/google/pprof). Only the Go pprof
#  writes the `pprof -proto` output that the profiling server ingests.
#  google/pprof has no release tags, so PPROF_COMMIT pins one commit.
#  pprof needs Go 1.25 or newer.
#
RUN GO_VERSION=1.27.1 && \
    GO_SHA256_AMD64=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445 && \
    GO_SHA256_ARM64=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec && \
    PPROF_COMMIT=d6c3cb2f37ec22719bbaf5eb031d9a46635cb5b2 && \
    case "$(uname -m)" in \
        x86_64)  GO_ARCH=amd64; GO_SHA256=$GO_SHA256_AMD64 ;; \
        aarch64) GO_ARCH=arm64; GO_SHA256=$GO_SHA256_ARM64 ;; \
        *) echo "go toolchain: no sha256 pinned for $(uname -m)" >&2; exit 1 ;; \
    esac && \
    curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/go.tgz \
        "https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" && \
    echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm /tmp/go.tgz && \
    GOPATH=/tmp/gopath GOCACHE=/tmp/gocache GOBIN=/usr/local/bin CGO_ENABLED=0 \
        /usr/local/go/bin/go install "github.com/google/pprof@${PPROF_COMMIT}" && \
    rm -rf /usr/local/go /tmp/gopath /tmp/gocache

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
