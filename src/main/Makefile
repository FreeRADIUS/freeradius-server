#
# $Id$
#

include ../../Make.inc

SERVER_OBJS	= radiusd.o files.o util.o acct.o nas.o log.o valuepair.o \
		  version.o proxy.o exec.o auth.o timestr.o conffile.o \
		  modules.o radutmp.o xlat.o threads.o smux.o radius_snmp.o \
                  client.o request_list.o
INCLUDES	= ../include/radiusd.h ../include/conf.h ../include/autoconf.h

CFLAGS		+= -I../include
LDFLAGS		+= -L../lib
LIBS		+= -lradius 
MODULE_LIBS	= $(STATIC_MODULES)

#
#  Not using shared libraries, add in ALL known static modules
# at build time.
#
ifneq ($(USE_SHARED_LIBS),yes)
MODULE_LIBS	+= $(shell for x in ../modules/rlm_*/rlm_*.la;do echo -dlpreopen $$x;done)
endif

all:	radiusd radwho radzap raduse radclient

radiusd: $(SERVER_OBJS) ../lib/libradius.a
	$(LIBTOOL) --mode=link $(CC) -export-dynamic -dlopen self \
		$(CFLAGS) $(LDFLAGS) -o $@ \
		$(SERVER_OBJS) $(LIBS) $(LCRYPT) \
		$(PTHREADLIB) $(LIBLTDL) $(MODULE_LIBS) 

radiusd.o: radiusd.c $(INCLUDES)  ../include/request_list.h ../include/modules.h 
	$(CC) $(CFLAGS) -c radiusd.c

acct.o: acct.c $(INCLUDES) ../include/modules.h
	$(CC) $(CFLAGS) -c acct.c

files.o: files.c $(INCLUDES)
	$(CC) $(CFLAGS) -c files.c

util.o: util.c $(INCLUDES)
	$(CC) $(CFLAGS) -c util.c

nas.o:  nas.c $(INCLUDES)
	$(CC) $(CFLAGS) -c nas.c

log.o:  log.c $(INCLUDES)
	$(CC) $(CFLAGS) -c log.c

conffile.o: conffile.c $(INCLUDES) ../include/modules.h
	$(CC) $(CFLAGS) -c conffile.c

timestr.o: timestr.c $(INCLUDES)
	$(CC) $(CFLAGS) -c timestr.c

modules.o:  modules.c $(INCLUDES)
	$(CC) $(CFLAGS) $(INCLTDL) -c modules.c

radutmp.o:  radutmp.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radutmp.c

session.o:  session.c $(INCLUDES) ../include/modules.h
	$(CC) $(CFLAGS) -c session.c

proxy.o:  proxy.c $(INCLUDES)
	$(CC) $(CFLAGS) -c proxy.c

exec.o:  exec.c $(INCLUDES)
	$(CC) $(CFLAGS) -c exec.c

auth.o:  auth.c $(INCLUDES) ../include/modules.h
	$(CC) $(CFLAGS) -c auth.c

valuepair.o:  valuepair.c $(INCLUDES)
	$(CC) $(CFLAGS) -c valuepair.c

version.o: version.c $(INCLUDES)
	$(CC) $(CFLAGS) -o version.o -c version.c

xlat.o: xlat.c $(INCLUDES)
	$(CC) $(CFLAGS) -o xlat.o -c xlat.c

threads.o: threads.c $(INCLUDES)
	$(CC) $(CFLAGS) -o threads.o -c threads.c

smux.o: smux.c $(INCLUDES)
	$(CC) $(CFLAGS) -o smux.o -c smux.c

radius_snmp.o: radius_snmp.c $(INCLUDES)
	$(CC) $(CFLAGS) -o radius_snmp.o -c radius_snmp.c

radclient: radclient.o ../lib/libradius.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o radclient radclient.o $(LIBS)

radclient.o: radclient.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radclient.c

builddbm: builddbm.o files_b.o log.o
	$(CC) $(LDFLAGS) -o builddbm builddbm.o files_b.o log.o $(LDBM) $(LIBS)

builddbm.o: builddbm.c
	$(CC) $(CFLAGS) -c builddbm.c

radwho.o: radwho.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radwho.c

radwho: radwho.o util.o nas.o client.o log.o
	$(CC) $(LDFLAGS) -o radwho radwho.o util.o nas.o client.o log.o $(LIBS)

raduse: raduse.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o raduse raduse.o $(LIBS)

radzap.o: radzap.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radzap.c

radzap: radzap.o util.o nas.o radutmp.o log.o client.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o radzap radzap.o util.o nas.o radutmp.o log.o client.o $(LIBS)

clean:
	rm -rf *.o *.so *~ modules_static.h radiusd radwho raduse \
		radclient radzap builddbm .libs

install:
	$(INSTALL) -d -m 755			$(R)$(sbindir)
	$(LIBTOOL) --mode=install $(INSTALL) -m 755 -s radiusd	$(R)$(sbindir)
	$(INSTALL) -m 755    checkrad.pl	$(R)$(sbindir)/checkrad
	$(INSTALL) -d -m 755			$(R)$(bindir)
	$(INSTALL) -m 755 -s radwho raduse	$(R)$(bindir)
	$(INSTALL) -m 755 -s radzap		$(R)$(bindir)
	$(INSTALL) -m 755    radlast		$(R)$(bindir)
	$(INSTALL) -m 755    radtest radclient	$(R)$(bindir)
	$(INSTALL) -d -m 755			$(R)$(logdir)
	$(INSTALL) -d -m 755			$(R)$(radacctdir)
