TARGET		= rlm_mschap
SRCS		= rlm_mschap.c deskey.c desport.c md4c.c smbpass.c
HEADERS		= md4.h des.h
RLM_CFLAGS	=

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)
