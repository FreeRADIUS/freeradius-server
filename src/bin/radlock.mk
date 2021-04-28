TARGET		:= radlock
SOURCES		:= radlock.c

TGT_PREREQS	:= libfreeradius-util.a

TGT_LDLIBS	:= $(LIBS)
