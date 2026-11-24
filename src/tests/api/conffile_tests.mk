TARGET		:= conffile_tests
SOURCES		:= conffile_tests.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=
