TARGET		:= radattr
SOURCES		:= radattr.c parser.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
