ARG from=DOCKER_IMAGE
FROM ${from}

#
#  Install profiling tools
#
#    valgrind / cachegrind
#    kcachegrind
#    gperftools
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

include(`common.freeradius-profile-build.m4')dnl

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
