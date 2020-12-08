#
#  Functions for comparing versions, taken from:
#
#    https://stackoverflow.com/a/15637871/2568535
#
S		:=
SP		:= $S $S
str.eq		= $(if $(subst $1,,$2),$S,T)
str.le		= $(call str.eq,$(word 1,$(sort $1 $2)),$1)
mklist		= $(eval __tmp := $1)$(foreach i,0 1 2 3 4 5 6 7 8 9,$(eval __tmp := $$(subst $$i,$$i ,$(__tmp))))$(__tmp)
shift		= $(wordlist 2, $(words $1), $1)
num.le		= $(eval __tmp1 := $(call mklist,$1))$(eval __tmp2 := $(call mklist,$2))$(if $(call str.eq,$(words $(__tmp1)),$(words $(__tmp2))),$(call str.le,$1,$2),$(call str.le,$(words $(__tmp1)),$(words $(__tmp2))))
list.strip	= $(eval __flag := 1)$(foreach d,$1,$(if $(__flag),$(if $(subst 0,,$d),$(eval __flag :=)$d,$S),$d))
gen.cmpstr	= $(eval __Tmp1 := $(subst ., ,$1))$(eval __Tmp2 := $(subst ., ,$2))$(foreach i,$(__Tmp1),$(eval j := $(word 1,$(__Tmp2)))$(if $j,$(if $(call str.eq,$i,$j),0,$(if $(call num.le,$i,$j),L,G)),G)$(eval __Tmp2 := $$(call shift,$(__Tmp2))))$(if $(__Tmp2), L)
ver.lt 		= $(call str.eq,$(word 1,$(call list.strip,$(call gen.cmpstr,$1,$2))),L)

#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
VERSION		:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""

#  Require cURL >= 7.56.0
CURL_TOO_OLD := $(call ver.lt,$(VERSION),7.56.0)

ifneq "$(CURL_TOO_OLD)" "T"
TARGET		:= rlm_smtp.a
TGT_PREREQS	+= libfreeradius-curl.a
endif

endif

SOURCES		:= rlm_smtp.c
