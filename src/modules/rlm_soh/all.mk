TARGETNAME	:= rlm_soh

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= libfreeradius-soh$(L)
LOG_ID_LIB	= 48
