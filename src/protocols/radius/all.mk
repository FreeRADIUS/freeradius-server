#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius$(L)

SOURCES		:= base.c \
		   decode.c \
		   encode.c \
		   list.c \
		   packet.c \
		   tcp.c \
		   abinary.c \
		   client.c \
		   client_udp.c \
		   client_tcp.c \
		   id.c \
		   bio.c \
		   server.c \
		   server_udp.c

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-bio$(L) libfreeradius-util$(L)
