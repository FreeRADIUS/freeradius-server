#
#  Changes the behaviour of autoconf.h to undef definitions that would conflict
#  with module config.h files.
#
CFLAGS += -DIS_MODULE=1

SUBMAKEFILES := $(wildcard ${top_srcdir}/src/modules/rlm_*/all.mk)
