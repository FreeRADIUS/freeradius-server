TARGETNAME	:= rlm_radius
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_radius.c track.c

TGT_PREREQS	:= libfreeradius-radius$(L) libfreeradius-bio-config$(L) libfreeradius-bio$(L)
LOG_ID_LIB	= 39
