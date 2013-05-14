TARGET		:= radwho
SOURCES		:= radwho.c conffile.c log.c util.c parser.c map.c evaluate.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
