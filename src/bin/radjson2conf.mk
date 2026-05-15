#
#  Only build radjson2conf if libfreeradius-json (the json-c wrapper)
#  was configured.  Probe TARGETNAME via the lib's all.mk - it's empty
#  when json-c wasn't found at autoconf time.  Reset TARGET so a stale
#  value from the previous .mk in the pipeline doesn't sneak through.
#
TARGETNAME	:=
-include $(top_builddir)/src/lib/json/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGETNAME	:= radjson2conf
TARGET		:= $(TARGETNAME)$(E)
endif

SOURCES		:= radjson2conf.c

SRC_CFLAGS	+= -I$(top_builddir)/src/lib/json/
TGT_LDLIBS	+= $(LIBS) $(LCRYPT)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-json$(L)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
