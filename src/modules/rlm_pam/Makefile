TARGET	= rlm_pam
SRCS	= rlm_pam.c
LIBS	= -lpam -ldl

include ../rules.mak

config.mak:
	@../checkconfig -l LIBPAM pam_start -lpam -ldl
