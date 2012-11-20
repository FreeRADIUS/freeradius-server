TARGET		:= radattr
SOURCES		:= radattr.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
