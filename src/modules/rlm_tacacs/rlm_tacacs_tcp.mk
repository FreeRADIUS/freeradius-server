TARGETNAME	:= rlm_tacacs_tcp
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_tacacs_tcp.c

TGT_PREREQS	:= libfreeradius-tacacs$(L)
