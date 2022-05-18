-include src/modules/rlm_sql/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_sqlippool
  TARGET	:= $(TARGETNAME)$(L)

  # Be sure to NOT include the rlm_sql drivers
  SUBMAKEFILES	:=
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:= -I$(top_builddir)/src/modules/rlm_sql
TGT_LDLIBS	:=
