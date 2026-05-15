#
#  Only build radmod2json if libjson-c was found at configure time.
#  Probe via rlm_json's TARGETNAME - it's empty when json-c wasn't
#  detected, populated otherwise.  The same all.mk also gives us
#  $(mod_cflags) / $(mod_ldflags) so we inherit the json-c include
#  and link flags directly from the autoconf probe.
#
TARGETNAME	:=
-include $(top_builddir)/src/modules/rlm_json/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGET		:= radmod2json
endif

SOURCES		:= radmod2json.c

TGT_LDLIBS	+= $(LIBS)
TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
