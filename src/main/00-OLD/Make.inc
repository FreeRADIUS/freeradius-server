#
# Makefile	RADIUS - 
#		Remote Authentication Dial In User Service
#
#

SERVER_OBJS    = radiusd.o dict.o files.o util.o md5.o attrprint.o \
			acct.o radius.o pam.o log.o version.o proxy.o \
			exec.o auth.o timestr.o cache.o
SERVERDBM_OBJS = radiusddbm.o dict.o filesdbm.o util.o md5.o attrprint.o \
			acct.o radius.o pam.o log.o versiondbm.o proxy.o \
			exec.o auth.o timestr.o cache.o
SERVER_SRCS    = radiusd.c dict.c files.c util.c md5.c attrprint.c acct.c \
			radius.c pam.c log.c version.c proxy.c \
			exec.c auth.c timestr.c cache.c
INCLUDES       = radius.h conf.h

all:	radiusd radwho radzap raduse radtest

dbm:	radiusd.dbm builddbm

radiusd: $(SERVER_OBJS)
	$(CC) $(LDFLAGS) -o radiusd $(SERVER_OBJS) $(LIBS) $(LCRYPT) $(PAMLIB)

radiusd.dbm: $(SERVERDBM_OBJS)
	$(CC) $(LDFLAGS) -o radiusd.dbm $(SERVERDBM_OBJS) $(LIBS) $(LCRYPT) \
			 $(DBMLIB) $(PAMLIB)

radiusd.o: radiusd.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radiusd.c

radiusddbm.o: radiusd.c $(INCLUDES)
	$(CC) $(CFLAGS) $(DBM) -c radiusd.c -o radiusddbm.o

acct.o: acct.c $(INCLUDES)
	$(CC) $(CFLAGS) -c acct.c

attrprint.o: attrprint.c $(INCLUDES)
	$(CC) $(CFLAGS) -c attrprint.c

dict.o: dict.c $(INCLUDES)
	$(CC) $(CFLAGS) -c dict.c

files.o: files.c $(INCLUDES)
	$(CC) $(CFLAGS) $(PAM) -c files.c

filesdbm.o: files.c $(INCLUDES)
	$(CC) $(CFLAGS) $(DBM) $(PAM) -o filesdbm.o -c files.c

radius.o: radius.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radius.c

util.o: util.c $(INCLUDES)
	$(CC) $(CFLAGS) -c util.c

pam.o:  pam.c $(INCLUDES)
	$(CC) $(CFLAGS) $(PAM) -c pam.c

cache.o:  cache.c $(INCLUDES)
	$(CC) $(CFLAGS) -c cache.c 

proxy.o:  proxy.c $(INCLUDES)
	$(CC) $(CFLAGS) -c proxy.c

exec.o:  exec.c $(INCLUDES)
	$(CC) $(CFLAGS) -c exec.c

auth.o:  auth.c $(INCLUDES)
	$(CC) $(CFLAGS) $(PAM) -c auth.c

version.o: version.c $(INCLUDES)
	$(CC) $(CFLAGS) -o version.o -c version.c

versiondbm.o: version.c $(INCLUDES)
	$(CC) $(CFLAGS) $(DBM) -o versiondbm.o -c version.c

radtest: radtest.o md5.o util.o dict.o attrprint.o log.o
	$(CC) $(LDFLAGS) -o radtest radtest.o md5.o util.o \
		dict.o attrprint.o log.o $(LIBS)

radtest.o: radtest.c $(INCLUDES)
	$(CC) $(CFLAGS) -c radtest.c

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c md5.c

builddbm: builddbm.o
	$(CC) $(LDFLAGS) -o builddbm builddbm.o $(DBMLIB) $(LIBS)

builddbm.o: builddbm.c
	$(CC) $(CFLAGS) -c $(DBM) builddbm.c

radwho: radwho.o util.o
	$(CC) $(LDFLAGS) -o radwho radwho.o util.o $(LIBS)

raduse: raduse.o
	$(CC) $(LDFLAGS) -o raduse raduse.o $(LIBS)

radzap: radzap.o util.o
	$(CC) $(LDFLAGS) -o radzap radzap.o util.o $(LIBS)

lint:
	-lint -hbacvx -DLINT $(SERVER_SRCS)
	-lint -hbacvx -DLINT ../radpass.c ../md5.c ../util.c

clean:
	rm -f *.o radiusd radwho raduse radtest radzap builddbm radiusd.dbm
	rm -f ../build ../debian/substvars ../debian/files

install:
	install -m 755 -s radiusd $(SBINDIR)/radiusd
	install -m 755 -s radwho  $(BINDIR)
	install -m 755 -s raduse  $(BINDIR)
	install -m 755 -s radzap  $(BINDIR)
	install -m 755    checkrad.pl $(SBINDIR)/checkrad
	install -m 755    radlast $(BINDIR)

