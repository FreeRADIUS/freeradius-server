TARGET		:= radwho
SOURCES		:= radwho.c conffile.c log.c util.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
