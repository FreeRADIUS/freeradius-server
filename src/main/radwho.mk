TARGET		:= radwho
SOURCES		:= radwho.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)
