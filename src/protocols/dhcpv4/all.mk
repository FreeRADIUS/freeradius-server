#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dhcpv4.a

SOURCES		:= base.c \
		   decode.c \
		   encode.c \
		   packet.c \
		   pcap.c \
		   raw.c \
		   udp.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT
TGT_LDLIBS	:= $(PCAP_LIBS)
TGT_LDFLAGS     := $(PCAP_LDFLAGS)
TGT_PREREQS	:= libfreeradius-util.a
