TARGET		:= libfreeradius-bfd$(L)

SOURCES		:= base.c encode.c decode.c

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-internal$(L)
