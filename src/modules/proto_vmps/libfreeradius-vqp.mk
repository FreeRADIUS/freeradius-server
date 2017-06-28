#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-vqp.a

SOURCES		:= vqp.c

SRC_CFLAGS	:= -I$(top_builddir)/src

TGT_PREREQS	:= libfreeradius-util.a
