-include src/modules/rlm_sql/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_sqlhpwippool
  TARGET	:= $(TARGETNAME).a

  # Be sure to NOT include the rlm_sql drivers
  SUBMAKEFILES	:= 
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:= 
SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_sql
TGT_LDLIBS	:= 
