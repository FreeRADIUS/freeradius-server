# must be first
include config.mak

TARGET	= rlm_pam
SRCS	= rlm_pam.c
LIBS	= -lpam -ldl

# over-ride the previous assignment if we're not building anything
ifeq ($(LIBPAM),)
TARGET	=
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBPAM pam_start -lpam -ldl
