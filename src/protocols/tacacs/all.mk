#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-tacacs.a
SOURCES		:= base.c decode.c encode.c
SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src
TGT_PREREQS	:= libfreeradius-util.a
