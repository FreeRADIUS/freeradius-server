TARGETNAME	:= rlm_totp

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= libfreeradius-totp$(L)

LOG_ID_LIB	= 53
