TARGETNAME := process_dns

TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-dns$(L)
