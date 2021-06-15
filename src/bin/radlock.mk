TARGET		:= radlock
SOURCES		:= radlock.c

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)
TGT_PREREQS	:= libfreeradius-util.a
