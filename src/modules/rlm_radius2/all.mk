#
#  For now this is tracked in Git, but isn't part of the
#  normal build.
#
ifneq "${WITH_RADIUS2}" ""
SUBMAKEFILES := rlm_radius.mk
endif
