TARGET		:= radconf2xml
SOURCES		:= radconf2xml.c util.c log.c conffile.c parser.c map.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
