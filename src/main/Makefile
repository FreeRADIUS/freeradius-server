#
# $Id$
#

include ../../Make.inc

SERVER_OBJS	= radiusd.o files.o util.o acct.o nas.o log.o valuepair.o \
		  version.o proxy.o exec.o auth.o timestr.o conffile.o \
		  modules.o radutmp.o xlat.o threads.o
INCLUDES	= ../include/radiusd.h ../include/conf.h ../include/modules.h \
		  ../include/autoconf.h

CFLAGS		+= -I../include -I../libltdl
LDFLAGS		+= -L../lib
LIBS		+= -lradius

#
# Pick up the static module libraries and linker flags.
#
STATIC_MODULE_LIBS	= $(wildcard ../modules/lib/*.a)
STATIC_MODULE_LDFLAGS	= $(shell cat ../modules/lib/STATIC_MODULE_LDFLAGS)

all:	radiusd radwho radzap raduse radclient $(BUILDDBM)

radiusd: $(SERVER_OBJS) ../lib/libradius.a
	$(LIBTOOL) --mode=link $(CC) -export-dynamic -dlopen \
		$(CFLAGS) $(LDFLAGS) -o $@ \
		$(SERVER_OBJS) $(LIBS) $(LDBM) $(LCRYPT) $(PTHREADLIB) \
		$(MODULE_LIBS) ../libltdl/libltdl.la

radiusd.o: radiusd.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radiusd.c

acct.o: acct.c $(INCLUDES)
	$(CC) $(CFLAGS) -c acct.c

files.o: files.c $(INCLUDES)
	$(CC) $(CFLAGS) -c files.c

files_b.o: files.c $(INCLUDES)
	$(CC) $(CFLAGS) -DBUILDDBM -o files_b.o -c files.c

util.o: util.c $(INCLUDES)
	$(CC) $(CFLAGS) -c util.c

nas.o:  nas.c $(INCLUDES)
	$(CC) $(CFLAGS) -c nas.c

modules.o:  modules.c $(INCLUDES) modules_static.h
	$(CC) $(CFLAGS) -c modules.c

radutmp.o:  radutmp.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radutmp.c

proxy.o:  proxy.c $(INCLUDES)
	$(CC) $(CFLAGS) -c proxy.c

exec.o:  exec.c $(INCLUDES)
	$(CC) $(CFLAGS) -c exec.c

auth.o:  auth.c $(INCLUDES)
	$(CC) $(CFLAGS) -c auth.c

valuepair.o:  valuepair.c $(INCLUDES)
	$(CC) $(CFLAGS) -c valuepair.c

version.o: version.c $(INCLUDES)
	$(CC) $(CFLAGS) -o version.o -c version.c

xlat.o: xlat.c $(INCLUDES)
	$(CC) $(CFLAGS) -o xlat.o -c xlat.c

threads.o: threads.c $(INCLUDES)
	$(CC) $(CFLAGS) -o threads.o -c threads.c

radclient: radclient.o ../lib/libradius.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o radclient radclient.o $(LIBS)

radclient.o: radclient.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radclient.c

builddbm: builddbm.o files_b.o log.o
	$(CC) $(LDFLAGS) -o builddbm builddbm.o files_b.o log.o $(LDBM) $(LIBS)

builddbm.o: builddbm.c
	$(CC) $(CFLAGS) -c builddbm.c

radwho: radwho.o util.o
	$(CC) $(LDFLAGS) -o radwho radwho.o util.o $(LIBS)

raduse: raduse.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o raduse raduse.o $(LIBS)

modules_static.h: modules_static.h.in
	rm -f modules_static.h
	cp modules_static.h.in modules_static.h
	./makemodules.sh static $(MODULES) >> modules_static.h

radzap: radzap.o util.o nas.o radutmp.o log.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o radzap radzap.o util.o nas.o radutmp.o log.o $(LIBS)

clean:
	rm -f *.o *.so *~ modules_static.h radiusd radwho raduse \
		radclient radzap builddbm

install:
	install -d -m 755			$(sbindir)
	$(LIBTOOL) install -m 755 -s radiusd	$(sbindir)
	install -m 755    checkrad.pl		$(sbindir)/checkrad
	install -d -m 755			$(bindir)
	install -m 755 -s radwho raduse		$(bindir)
	install -m 755 -s radzap $(BUILDDBM)	$(bindir)
	install -m 755    radlast		$(bindir)
	install -m 755    radtest radclient	$(bindir)
	install -d -m 755			$(logdir)
	install -d -m 755			$(radacctdir)
