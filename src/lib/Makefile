
include ../../Make.inc

SRCS		= dict.c print.c radius.c valuepair.c token.c misc.c \
		log.c filters.c missing.c md4.c md5.c sha1.c \
		hmac.c hmacsha1.c snprintf.c isaac.c crypt.c \
		udpfromto.c rbtree.c

INCLUDES	= ../include/radius.h ../include/libradius.h \
		  ../include/missing.h ../include/autoconf.h

CFLAGS		+= -D_LIBRADIUS -I../include 

# if you have problems with things that need SHA1-HMAC, this will
# dump the key and the input to the hash so you can compare to what
# the other end is doing.
CFLAGS += -DHMAC_SHA1_DATA_PROBLEMS

all:	static dynamic

TARGET=$(LIBPREFIX)radius

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
	$(CC) $(CFLAGS) -c $< -o $@

%.lo : %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<


$(TARGET).a: $(STATIC_OBJS)
	$(LIBTOOL) --mode=link $(LD) \
	-module -static $(CFLAGS) $^ -o $@ 


ifneq ($(USE_SHARED_LIBS),yes)
LINK_MODE=-static
endif

$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	-module $(LINK_MODE) $(CFLAGS) -o $@ -rpath $(libdir) $^ 

static: $(TARGET).a

dynamic: $(TARGET).la

clean:
	rm -f *.o *.lo $(TARGET).a $(TARGET).la
	rm -rf .libs

install: static dynamic
	$(LIBTOOL) --mode=install $(INSTALL) -c \
		$(TARGET).la $(R)$(libdir)/$(TARGET).la;
	rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la;
	ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la
