#  This needs to be cleared explicitly, as the libfreeradius-redis.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/kafka/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_kafka
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	+= -I$(top_builddir)/lib/kafka
TGT_PREREQS	:= libfreeradius-kafka$(L)
LOG_ID_LIB	= 61
