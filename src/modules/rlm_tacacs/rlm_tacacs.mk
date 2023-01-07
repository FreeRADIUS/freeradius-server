TARGETNAME	:= rlm_tacacs
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_tacacs.c

TGT_PREREQS	:= libfreeradius-tacacs$(L)
LOG_ID_LIB	= 59
