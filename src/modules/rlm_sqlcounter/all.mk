-include src/modules/rlm_sql/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_sqlcounter
  TARGET	:= $(TARGETNAME)$(L)

  # Be sure to NOT include the rlm_sql drivers
  SUBMAKEFILES	:= 
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:= $(rlm_sql_CFLAGS) -I$(top_builddir)/src/modules/rlm_sql
TGT_LDLIBS	:= $(rlm_sql_LDLIBS)
