TARGET		:= radattr
SOURCES		:= radattr.c parser.c xlat.c util.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
