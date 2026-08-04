TARGET		:= libfreeradius-bfd$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= base.c encode.c decode.c

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-internal$(L)
