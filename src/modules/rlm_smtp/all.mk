#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
VERSION		:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""

#  Require cURL >= 7.56.0
CURL_X		:= $(word 1,$(subst ., ,$(VERSION)))
CURL_Y		:= $(word 2,$(subst ., ,$(VERSION)))
CURL_GOOD	:= $(shell test $(CURL_X) -gt 7 -o \( $(CURL_X) -eq 7 -a $(CURL_Y) -ge 56 \) && echo true)

ifeq ($(CURL_GOOD),true)
TARGET		:= rlm_smtp.a
TGT_PREREQS	+= libfreeradius-curl.a
endif

endif

SOURCES		:= rlm_smtp.c
