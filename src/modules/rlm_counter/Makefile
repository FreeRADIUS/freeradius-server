#
#  This file is just like 'Makefile', but with the comments stripped out.
#  It shows just how small the 'Makefile' really can be.
#
include config.mak

TARGET		= rlm_counter
SRCS		= rlm_counter.c
HEADERS		= 
RLM_CFLAGS	=
RLM_LIBS	= -lgdbm

ifeq ($(LIBGDBM),)
TARGET=
endif

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

config.mak config.h:
	@../checkconfig -l LIBGDBM gdbm_open -lgdbm
