
include ../../Make.inc

OBJS		= dict.o print.o radius.o valuepair.o token.o misc.o \
		log.o filters.o missing.o md5.o snprintf.o

INCLUDES	= ../include/radius.h ../include/libradius.h \
		  ../include/missing.h ../include/autoconf.h

CFLAGS		+= -D_LIBRADIUS -I../include

all:	$(LIBPREFIX)radius.a

$(LIBPREFIX)radius.a: $(OBJS)
	$(LIBTOOL) --mode=link $(LD) $(OBJS) -o $(LIBPREFIX)radius.a

#	$(AR) rv $(LIBPREFIX)radius.a $(OBJS)
#	$(RANLIB) $(LIBPREFIX)radius.a

filters.o: filters.c $(INCLUDES)
	$(CC) $(CFLAGS) -c filters.c

print.o: print.c $(INCLUDES)
	$(CC) $(CFLAGS) -c print.c

dict.o: dict.c $(INCLUDES)
	$(CC) $(CFLAGS) -c dict.c

radius.o: radius.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radius.c

valuepair.o: valuepair.c $(INCLUDES)
	$(CC) $(CFLAGS) -c valuepair.c

token.o: token.c $(INCLUDES)
	$(CC) $(CFLAGS) -c token.c

misc.o: misc.c $(INCLUDES)
	$(CC) $(CFLAGS) -c misc.c

log.o:	log.c $(INCLUDES)
	$(CC) $(CFLAGS) -c log.c

missing.o: missing.c $(INCLUDES)
	$(CC) $(CFLAGS) -c missing.c

md5.o: md5.c ../include/md5.h
	$(CC) $(CFLAGS) -c md5.c

snprntf.o: snprintf.c $(INCLUDES)
	$(CC) $(CFLAGS) -c snprintf.c

clean:
	rm -f *.o $(LIBPREFIX)radius.a

install:

