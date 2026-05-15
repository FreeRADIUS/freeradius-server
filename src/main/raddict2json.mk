#
#  Only build raddict2json if libjson-c was found at configure time.
#  Probe via rlm_json's TARGETNAME - it's empty when json-c wasn't
#  detected.  Inherits json-c include / link flags from the same
#  autoconf machinery the module uses.
#
TARGETNAME	:=
-include $(top_builddir)/src/modules/rlm_json/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGET		:= raddict2json
endif

SOURCES		:= raddict2json.c

TGT_LDLIBS	+= $(LIBS)
TGT_PREREQS	:= libfreeradius-radius.a
