#
#  Changes the behaviour of autoconf.h to undef definitions that would conflict
#  with module config.h files.
#
CFLAGS += -DIS_MODULE=1

#
#  Load in all of the module makefiles, including ones which
#  have not yet been configured.  We do the "sort" to remove duplicates.
#
SUBMAKEFILES := $(sort $(wildcard ${top_srcdir}/src/modules/rlm_*/all.mk) \
		$(patsubst %.in,%,$(wildcard ${top_srcdir}/src/modules/rlm_*/all.mk.in)))
