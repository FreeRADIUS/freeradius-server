#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius.a

SOURCES		:= base.c \
		   decode.c \
		   encode.c \
		   list.c \
		   packet.c \
		   tcp.c

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-util.a
