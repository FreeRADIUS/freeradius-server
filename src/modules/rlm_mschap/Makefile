#
# Makefile
#
# Version:	$Id$
#

TARGET		= rlm_mschap
SRCS		= rlm_mschap.c mschap.c smbdes.c opendir.c
HEADERS		= mschap.h smbdes.h
RLM_CFLAGS	=
RLM_LDFLAGS	=
RLM_LIBS	=
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt-install

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(LT_OBJS): $(HEADERS)

smbencrypt: smbencrypt.lo smbdes.lo $(LIBRADIUS)
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $(RLM_LDFLAGS) \
		-o $@ $^ $(RLM_LIBS) $(LIBS)

smbencrypt-install:
	$(INSTALL) -d -m 755 $(R)$(bindir)
	$(LIBTOOL) --mode=install $(INSTALL) -m 755 $(INSTALLSTRIP) \
		smbencrypt$(EXEEXT) $(R)$(bindir)
