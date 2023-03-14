TARGETNAME	:= process_bfd

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c
SRC_CFLAGS	:= -I$(top_builddir)/src/listen

TGT_PREREQS	:= libfreeradius-bfd$(L)
