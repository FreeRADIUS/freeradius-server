TARGET		= rlm_mschap
SRCS		= rlm_mschap.c deskey.c desport.c md4c.c smbpass.c sha1.c
HEADERS		= md4.h des.h smbpass.h sha1.h
RLM_CFLAGS	=
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

smbencrypt: $(STATIC_OBJS)
	$(CC) $(LDFLAGS) -osmbencrypt smbencrypt.c deskey.o desport.o md4c.o smbpass.o