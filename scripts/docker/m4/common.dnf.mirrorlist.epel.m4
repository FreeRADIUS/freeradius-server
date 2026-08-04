#
#  Snapshot the EPEL mirror lists, which only exist once epel-release
#  is installed (the script itself arrives via common.dnf.retries.m4).
#
RUN dnf-mirrorlist-snapshot epel
