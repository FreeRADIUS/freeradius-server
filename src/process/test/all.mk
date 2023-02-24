TARGETNAME := process_test

TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-util$(L)

TGT_INSTALLDIR	:=
