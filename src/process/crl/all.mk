TARGETNAME	:= process_crl

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

#TGT_PREREQS	:= libfreeradius-tacacs$(L)
