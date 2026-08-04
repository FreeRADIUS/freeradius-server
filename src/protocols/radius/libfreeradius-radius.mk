#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= base.c \
		   decode.c \
		   encode.c \
		   list.c \
		   packet.c \
		   tcp.c \
		   abinary.c

TGT_PREREQS	:= libfreeradius-util$(L)
