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

smbencrypt: smbencrypt.o smbpass.o $(HEADERS)
	$(CC) -I../../include $(LDFLAGS) -o smbencrypt smbencrypt.o ../../lib/libradius.a

smbencrypt-install:
	$(INSTALL) -d -m 755 $(R)$(bindir)
	$(INSTALL) -m 755 $(INSTALLSTRIP) smbencrypt $(R)$(bindir)
