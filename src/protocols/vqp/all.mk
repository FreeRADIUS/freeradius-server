#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-vqp.a

SOURCES		:= vqp.c base.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT

TGT_PREREQS	:= libfreeradius-util.a
