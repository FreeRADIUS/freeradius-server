#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-dhcpv6$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= base.c \
		   decode.c \
		   encode.c

SRC_CFLAGS	:= -DNO_ASSERT
TGT_PREREQS	:= libfreeradius-util$(L)
