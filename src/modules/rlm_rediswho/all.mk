-include src/modules/rlm_redis/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_rediswho
  TARGET	:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

#
#  Append SRC_CFLAGS and leave TGT_LDLIBS alone
#
SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_redis
