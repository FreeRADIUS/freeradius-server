TARGETNAME	:= rlm_chap

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= libfreeradius-util$(L)
LOG_ID_LIB	= 4
