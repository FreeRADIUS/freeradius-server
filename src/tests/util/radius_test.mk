TARGET := radius_test

SOURCES		:= radius_test.c ${top_srcdir}/src/main/tls/global.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
