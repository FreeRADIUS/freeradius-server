TARGET		= rlm_mschap
SRCS		= rlm_mschap.c smbdes.c
HEADERS		= 
RLM_CFLAGS	=
RLM_LDFLAGS	= 
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt-install

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

smbencrypt: smbencrypt.o smbdes.o $(HEADERS)
	$(CC) -I../../include $(LDFLAGS) -o smbencrypt smbencrypt.o smbdes.o ../../lib/libradius.a

smbencrypt-install:
	$(INSTALL) -d -m 755 $(R)$(bindir)
	$(INSTALL) -m 755 $(INSTALLSTRIP) smbencrypt$(EXEEXT) $(R)$(bindir)
