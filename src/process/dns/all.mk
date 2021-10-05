TARGETNAME := process_dns

TARGET		:= $(TARGETNAME).a

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-dns.a
