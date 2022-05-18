#  This needs to be cleared explicitly, as the libfreeradius-redis.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/redis/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_redis_ippool
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES	:= $(TARGETNAME).c

SRC_CFLAGS	+= -I$(top_builddir)/src/lib/redis
TGT_PREREQS	:= libfreeradius-redis$(L)
LOG_ID_LIB	= 42
