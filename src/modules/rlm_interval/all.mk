TARGETNAME	:= rlm_interval
TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= rlm_interval.c
TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-server$(L)
LOG_ID_LIB	= 64
