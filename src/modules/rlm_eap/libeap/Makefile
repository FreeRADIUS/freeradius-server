include ../../../../Make.inc

SRCS		= fips186prf.c eapcrypto.c eapcommon.c eapsimlib.c

INCLUDES	= 

CFLAGS		+= -DEAPLIB -I../../../include 

TARGET=$(LIBPREFIX)eap

all:	dynamic

dynamic: $(TARGET).la

STATIC_OBJS	= $(SRCS:.c=.o)
DYNAMIC_OBJS	= $(SRCS:.c=.lo)

$(STATIC_OBJS):  $(INCLUDES)
$(DYNAMIC_OBJS): $(INCLUDES)

#######################################################################
#
# define new rules
#
#######################################################################
%.o : %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $< -o $@

%.lo : %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<

$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	$(CFLAGS) -o $@ -rpath $(libdir) $^ ../../../lib/libradius.la
clean:
	rm -f *.o *.lo $(TARGET).a $(TARGET).la
	rm -rf .libs

install: $(TARGET).la
	$(LIBTOOL) --mode=install $(INSTALL) -c \
		$(TARGET).la $(R)$(libdir)/$(TARGET).la;
	rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la;
	ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la
