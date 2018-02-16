#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dhcpv6.a

SOURCES		:= base.c \
		   decode.c \
		   encode.c

TGT_PREREQS	:= libfreeradius-util.a
