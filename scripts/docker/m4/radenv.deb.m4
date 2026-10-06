ARG from=DOCKER_IMAGE
FROM ${from}

#
#  The 'radenv' image holds a developer build of FreeRADIUS from the
#  checkout, and the multi-server tests build the 'radenv' image for each
#  commit.  The crossbuild base image provides the toolchain, the build
#  dependencies, and the packages whose commands the tests run.  A build
#  of the 'radenv' image therefore only compiles and installs FreeRADIUS
#  from the checkout.  The build does not run `apt-get`, so an
#  unreachable package mirror does not stop the build.
#
define(`RADENV_CONFIGURE_ARGS', `')dnl
include(`common.radenv-build.m4')dnl

EXPOSE 1812/udp 1813/udp
CMD ["/bin/sh", "-c", "while true; do sleep 60; done"]
