-include libfreeradius-redis.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_redis
  TARGET	    := $(TARGETNAME).a
endif

SOURCES		    := $(TARGETNAME).c

SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_redis
TGT_PREREQS	:= libfreeradius-redis.a
