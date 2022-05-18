TARGETNAME	:= rlm_eap

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= . lib/base

TGT_PREREQS	:= libfreeradius-eap$(L)
LOG_ID_LIB	= 15
