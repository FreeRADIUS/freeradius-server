TARGET		:= radwho
SOURCES		:= radwho.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)
