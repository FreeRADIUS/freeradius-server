#
#  Build libkqueue from source as proper .debs (libkqueue0, libkqueue-dev,
#  libkqueue-dbg) so downstream dpkg-checkbuilddeps / Build-Depends steps
#  find -dev and so a debugger sees symbols.
#
#  Gated to architectures the NetworkRADIUS extras repo doesn't carry
#  (currently anything that isn't amd64). On amd64 we install libkqueue
#  from NR's extras repo via common.deb.nr-extras.m4, which keeps the
#  shlibs version in lockstep with what NR's freeradius packages were
#  built against -- otherwise libfreeradius4's `(= <ver>)` libkqueue
#  dep rejects the source-built version at runtime install time.
#
#  cpack's DEB generator emits a -dbg package whenever the build produces
#  unstripped objects; RelWithDebInfo with explicit C flags overrides
#  libkqueue's default -O2 -g -DNDEBUG so the symbols actually survive.
#
RUN mkdir -p /opt/libkqueue-debs && \
    case "$(dpkg --print-architecture)" in \
        amd64) \
            echo "libkqueue: skipping source build, NetworkRADIUS extras ships amd64" ;; \
        *) \
            apt-get install -y --no-install-recommends cmake git build-essential file && \
            git clone --depth 1 https://github.com/mheily/libkqueue.git /tmp/libkqueue && \
            cd /tmp/libkqueue && \
            cmake -G "Unix Makefiles" \
                -DCMAKE_INSTALL_PREFIX=/usr \
                -DCMAKE_INSTALL_LIBDIR=lib \
                -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                -DCMAKE_C_FLAGS_RELWITHDEBINFO="-g3 -O1 -fno-omit-frame-pointer -DNDEBUG" \
                -DCPACK_DEBIAN_PACKAGE_NAME=libkqueue0 \
                . && \
            make && \
            cpack -G DEB && \
            dpkg -i libkqueue*.deb && \
            cp libkqueue*.deb /opt/libkqueue-debs/ && \
            cd / && rm -rf /tmp/libkqueue \
            ;; \
    esac
