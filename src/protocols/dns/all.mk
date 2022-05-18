#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dns$(L)

SOURCES		:= base.c decode.c encode.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT
TGT_LDLIBS	:= $(PCAP_LIBS)
TGT_LDFLAGS     := $(PCAP_LDFLAGS)
TGT_PREREQS	:= libfreeradius-util$(L)
