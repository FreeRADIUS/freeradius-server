#
#  Include the library makefile to learn whether libfreeradius-ldap was
#  configured, and to pick up the OpenLDAP compiler and linker flags.
#  Every consumer of the library does the same.
#
TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

LDAP_SRC_CFLAGS	:= $(SRC_CFLAGS)
LDAP_TGT_LDLIBS	:= $(TGT_LDLIBS)

#
#  Clear the target variables the include set, this makefile only
#  lists submakefiles.
#
TARGET		:=
TGT_CATEGORY	:=
SOURCES		:=
SRC_CFLAGS	:=
TGT_LDLIBS	:=

ifneq "${TARGETNAME}" ""
SUBMAKEFILES	:= ldap_util_tests.mk
endif
