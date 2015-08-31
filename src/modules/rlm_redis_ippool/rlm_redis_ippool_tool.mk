#  This needs to be cleared explicitly, as the libfreeradius-redis.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/modules/rlm_redis/libfreeradius-redis.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_redis_ippool_tool
  TARGET	:= $(TARGETNAME)
endif

SOURCES		:= $(TARGETNAME).c
SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_redis

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a libfreeradius-redis.a
TGT_LDLIBS	:= $(TALLOC_LIBS)

MAN		:= rlm_redis_ippool_tool.8
