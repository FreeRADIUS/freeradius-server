#
# Makefile
#
# Version:      $Id$
#

include ../../Make.inc

SRCS		= dict.c filters.c hash.c hmac.c hmacsha1.c isaac.c log.c \
		  misc.c missing.c md4.c md5.c print.c radius.c rbtree.c \
		  sha1.c snprintf.c strlcat.c strlcpy.c token.c udpfromto.c \
		  valuepair.c fifo.c packet.c event.c getaddrinfo.c vqp.c \
		  heap.c dhcp.c tcp.c

LT_OBJS		= $(SRCS:.c=.$(LO))

INCLUDES	= ../include/radius.h ../include/libradius.h \
		  ../include/missing.h ../include/autoconf.h \
		  ../include/ident.h

CFLAGS		+= -D_LIBRADIUS -I$(top_builddir)/src

# if you have problems with things that need SHA1-HMAC, this will
# dump the key and the input to the hash so you can compare to what
# the other end is doing.
#CFLAGS += -DHMAC_SHA1_DATA_PROBLEMS

TARGET		= $(LIBPREFIX)freeradius-radius

# Define new rule for libtool objects
%.$(LO) : %.c
	@echo CC $<
	@$(COMPILE.c) $(CFLAGS) -c $<

.PHONY: all clean install reconfig
all: $(TARGET).$(LA)

$(TARGET).$(LA): $(LT_OBJS)
	@echo LINK $@ $^
	@$(LINK.lib) $@ $(LDFLAGS) $^

$(LT_OBJS): $(INCLUDES)

clean:
	@rm -f *.$(LO) $(TARGET).$(LA)
	@rm -rf .libs

install: all
	$(INSTALL) -d -m 755	$(R)$(libdir)
	$(LIBTOOL) --mode=install $(INSTALL) -c $(TARGET).la \
		$(R)$(libdir)/$(TARGET).la
	rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la;
	ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la

reconfig:
