#
#  Debug symbols for the FreeRADIUS runtime library closure. We use
#  `dnf debuginfo-install` (from dnf-plugins-core) because Rocky's
#  debug repo naming has shifted between versions; the plugin walks
#  the package metadata and enables whichever *-debug repo provides
#  the matching debuginfo rpm.
#
#  Per-package install with `|| true' fallback so a renamed / dropped
#  debuginfo doesn't wreck the whole layer; a WARNING line in the
#  build log flags any miss for operators.
#
RUN dnf install -y dnf-plugins-core && \
    for pkg in glibc openssl-libs libtalloc pcre2; do \
        dnf debuginfo-install -y "$pkg" || echo "WARNING: could not install debuginfo package: $pkg"; \
    done
