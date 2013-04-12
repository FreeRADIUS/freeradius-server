TARGET 		:= radmin

SOURCES		:= radmin.c conffile.c parser.c log.c util.c

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE) -ltalloc
