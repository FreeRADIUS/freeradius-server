#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-vmps$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= vmps.c base.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
