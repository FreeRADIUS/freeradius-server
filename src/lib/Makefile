
include ../../Make.inc

OBJS		= dict.o md5.o print.o radius.o valuepair.o token.o misc.o \
		log.o filters.o missing.o

INCLUDES	= ../include/radius.h ../include/libradius.h \
		  ../include/missing.h

CFLAGS		+= -D_LIBRADIUS -I../include

all:	libradius.a

libradius.a: $(OBJS)
	$(AR) rv libradius.a $(OBJS)
	$(RANLIB) libradius.a

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

missing.o:	missing.c $(INCLUDES)
	$(CC) $(CFLAGS) -c missing.c

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c md5.c

clean:
	rm -f *.o libradius.a

install:

