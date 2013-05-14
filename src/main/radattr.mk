TARGET		:= radattr
SOURCES		:= radattr.c parser.c xlat.c util.c map.c conffile.c log.c evaluate.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
