TARGETNAME	:= rlm_radius
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_radius.c

TGT_PREREQS	:= libfreeradius-radius$(L)
LOG_ID_LIB	= 39
