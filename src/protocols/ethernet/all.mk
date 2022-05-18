#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-ethernet$(L)

SOURCES		:= ethernet.c

SRC_CFLAGS	:= -DNO_ASSERT
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
