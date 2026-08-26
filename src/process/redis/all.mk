#  This needs to be cleared explicitly, as the libfreeradius-redis.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/redis/all.mk

ifneq "$(TARGETNAME)" ""
  TARGETNAME	:= process_redis
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-redis$(L)
