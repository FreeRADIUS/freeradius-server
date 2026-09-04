#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dhcpv4$(L)
TGT_CATEGORY	:= lib-protocol

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
TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
