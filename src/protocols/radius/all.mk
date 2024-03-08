#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius$(L)

SOURCES		:= base.c \
		   client.c \
		   client_udp.c \
		   client_tcp.c \
		   decode.c \
		   encode.c \
		   id.c \
		   list.c \
		   packet.c \
		   tcp.c \
		   abinary.c \
		   bio.c

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-bio$(L)
