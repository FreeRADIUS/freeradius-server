TARGET		= rlm_mschap
SRCS		= rlm_mschap.c smbpass.c
HEADERS		= smbpass.h
RLM_CFLAGS	=
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt-install

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

smbencrypt: $(STATIC_OBJS)
	$(CC) -I../../include $(LDFLAGS) -o smbencrypt smbencrypt.c deskey.o desport.o smbpass.o ../../lib/md4.o

smbencrypt-install:
	$(INSTALL) -d -m 755				$(R)$(bindir)
	$(INSTALL) -m 755 $(INSTALLSTRIP) smbencrypt $(R)$(bindir)
