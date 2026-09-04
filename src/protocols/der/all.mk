#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-der$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= base.c \
		   decode.c \
		   encode.c

SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT
TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
