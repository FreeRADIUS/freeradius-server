#!/bin/bash
#
#  Rewrite /etc/apt/sources.list.d/ubuntu.sources to use country mirrors
#  via the mirror+file: protocol, so apt tries nearby mirrors before
#  falling back.
#
#  This script handles both amd64 (archive.ubuntu.com) and arm64
#  (ports.ubuntu.com/ubuntu-ports) base URIs.  Country archive mirrors
#  also carry noble-security, so the security suite gets the same
#  mirror list with security.ubuntu.com as the last-resort fallback.
#
#  Repos not covered here:
#    LLVM (apt.llvm.org)                  - Fastly CDN, geo-distributed transparently
#    Network RADIUS (packages.networkradius.com) - our own repo, single origin by design
#    OpenResty (openresty.org)            - single origin, no public mirrors exist
#

set -e

SOURCES=/etc/apt/sources.list.d/ubuntu.sources
MIRRORS_DIR=/etc/apt/mirrors

mkdir -p "${MIRRORS_DIR}"

#
#  Fail over to the next mirror quickly rather than waiting the default
#  120s for a dead host to time out.
#
cat > /etc/apt/apt.conf.d/99-mirror-timeouts.conf <<'EOF'
Acquire::http::ConnectTimeout "5";
Acquire::https::ConnectTimeout "5";
EOF

#
#  amd64 archive mirrors
#
cat > "${MIRRORS_DIR}/ubuntu.list" <<'EOF'
http://ca.archive.ubuntu.com/ubuntu/
http://us.archive.ubuntu.com/ubuntu/
http://gb.archive.ubuntu.com/ubuntu/
http://archive.ubuntu.com/ubuntu/
EOF

#
#  Security mirrors - country archive mirrors carry noble-security too
#
cat > "${MIRRORS_DIR}/ubuntu-security.list" <<'EOF'
http://ca.archive.ubuntu.com/ubuntu/
http://us.archive.ubuntu.com/ubuntu/
http://gb.archive.ubuntu.com/ubuntu/
http://security.ubuntu.com/ubuntu/
EOF

#
#  arm64 / ports mirrors
#
cat > "${MIRRORS_DIR}/ubuntu-ports.list" <<'EOF'
http://ca.ports.ubuntu.com/ubuntu-ports/
http://us.ports.ubuntu.com/ubuntu-ports/
http://gb.ports.ubuntu.com/ubuntu-ports/
http://ports.ubuntu.com/ubuntu-ports/
EOF

#
#  Rewrite URIs in the deb822 sources file to point at the mirror lists above.
#
sed -i \
    -e "s|URIs: http://archive.ubuntu.com/ubuntu/|URIs: mirror+file:${MIRRORS_DIR}/ubuntu.list|" \
    -e "s|URIs: http://ports.ubuntu.com/ubuntu-ports/|URIs: mirror+file:${MIRRORS_DIR}/ubuntu-ports.list|" \
    -e "s|URIs: http://security.ubuntu.com/ubuntu/|URIs: mirror+file:${MIRRORS_DIR}/ubuntu-security.list|" \
    "${SOURCES}"
