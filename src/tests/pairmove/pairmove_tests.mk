TARGET		:= pairmove_tests
SOURCES		:= pairmove_tests.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)
TGT_INSTALLDIR	:=
