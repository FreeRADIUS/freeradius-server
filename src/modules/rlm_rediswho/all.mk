#  This needs to be cleared explicitly, as the libfreeradius-redis.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include src/modules/rlm_redis/libfreeradius-redis.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_rediswho
  TARGET        := $(TARGETNAME).a
endif

SOURCES     := $(TARGETNAME).c

#
#  Append SRC_CFLAGS and leave TGT_LDLIBS alone
#
SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_redis
TGT_PREREQS	:= libfreeradius-redis.a
