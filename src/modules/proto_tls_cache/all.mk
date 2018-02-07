TARGETNAME	:= proto_tls_cache

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tls_cache.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
