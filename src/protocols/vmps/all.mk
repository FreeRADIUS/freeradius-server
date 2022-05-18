#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-vmps$(L)

SOURCES		:= vmps.c base.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT

TGT_PREREQS	:= libfreeradius-util$(L)
