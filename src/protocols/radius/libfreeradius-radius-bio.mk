#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius-bio$(L)

SOURCES		:= client.c \
		   client_udp.c \
		   client_tcp.c \
		   id.c \
		   bio.c \
		   server.c \
		   server_udp.c

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-radius$(L) libfreeradius-bio$(L)
