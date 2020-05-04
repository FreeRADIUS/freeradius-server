#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-arp.a

SOURCES		:= base.c

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-util.a
