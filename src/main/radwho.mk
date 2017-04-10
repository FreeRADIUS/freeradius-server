TARGET		:= radwho
SOURCES		:= radwho.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
