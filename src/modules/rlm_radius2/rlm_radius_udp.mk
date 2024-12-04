TARGETNAME	:= rlm_radius_udp
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_radius_udp.c track.c

TGT_PREREQS	:= libfreeradius-radius$(L)
