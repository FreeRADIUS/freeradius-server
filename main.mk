uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

#
#  The tests depend on things in raddb, so we load those rules
#  first.
#
SUBMAKEFILES := $(call uniq,raddb/all.mk $(wildcard */all.mk))
