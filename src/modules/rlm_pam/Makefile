# must be first
include config.mak

TARGET	= rlm_pam
SRCS	= rlm_pam.c
LIBS	= $(LIBPAM)

# over-ride the previous assignment if we're not building anything
ifeq ($(LIBPAM),)
TARGET	=
endif

include ../rules.mak

# Look for PAM libraries using -lpam && -ldl. (Linux)
# If they aren't found there, (FreeBSD doesn't have libdl),
# then just use -lpam
config.mak:
	@../checkconfig -l LIBPAM pam_start "-lpam -ldl"
	@../checkconfig -l LIBPAM pam_start -lpam
