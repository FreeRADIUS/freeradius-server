#
#  For now this is tracked in Git, but isn't part of the
#  normal build.
#
ifneq "${WITH_RADIUS2}" ""
TARGETNAME	:= rlm_radius
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_radius.c track.c

TGT_PREREQS	:= libfreeradius-radius$(L) libfreeradius-bio-config$(L) libfreeradius-bio$(L)
LOG_ID_LIB	= 39

endif
