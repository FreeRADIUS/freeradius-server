TARGET		:= ldap_util_tests$(E)
SOURCES		:= ldap_util_tests.c

SRC_CFLAGS	:= $(LDAP_SRC_CFLAGS)
TGT_LDLIBS	:= $(LIBS) $(LDAP_TGT_LDLIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-ldap$(L) libfreeradius-server$(L) libfreeradius-unlang$(L) $(LIBFREERADIUS_UTIL)

TGT_INSTALLDIR	:=
