#
#  Only build radmod2json if libfreeradius-json (the json-c wrapper)
#  was configured.  Probe TARGETNAME via the lib's all.mk - it's empty
#  when json-c wasn't found at autoconf time.  Reset TARGET so a stale
#  value from the previous .mk in the pipeline doesn't sneak through.
#
TARGETNAME	:=
-include $(top_builddir)/src/lib/json/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGETNAME	:= radmod2json
TARGET		:= $(TARGETNAME)$(E)
endif

SOURCES		:= radmod2json.c

SRC_CFLAGS	+= -I$(top_builddir)/src/lib/json/
TGT_LDLIBS	+= $(LIBS) $(LCRYPT) $(LIBDL)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-json$(L)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
