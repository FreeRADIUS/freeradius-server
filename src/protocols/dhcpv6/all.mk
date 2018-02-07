#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dhcpv6.a

SOURCES		:= decode.c \
		   encode.c

TGT_PREREQS	:= libfreeradius-util.a
