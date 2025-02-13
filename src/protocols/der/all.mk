#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-der$(L)

SOURCES		:= base.c \
		   encode.c

#		   decode.c \


SRC_CFLAGS	:= -I$(top_builddir)/src -DNO_ASSERT
TGT_PREREQS	:= libfreeradius-util$(L)
