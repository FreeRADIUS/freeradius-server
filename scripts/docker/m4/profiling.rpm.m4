ARG from=DOCKER_IMAGE
FROM ${from}

#
#  Per-commit profiling image. The slow toolchain layer (valgrind /
#  kcachegrind / debuginfo / FlameGraph / inferno) lives in
#  profiling-deps and is refreshed periodically by docker-refresh.yml;
#  this layer just compiles FreeRADIUS with profiling-friendly CFLAGS
#  on top of it. See common.freeradius-profile-build.m4 for the CFLAGS
#  rationale.
#
include(`common.freeradius-profile-build.m4')dnl

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
