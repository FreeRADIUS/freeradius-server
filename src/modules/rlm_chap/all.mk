TARGETNAME	:= rlm_chap

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= libfreeradius-radius$(L)
LOG_ID_LIB	= 4
