# add this dependency BEFORE including the other submakefiles.
all:

SUBMAKEFILES := include/all.mk \
	lib/all.mk \
	protocols/all.mk \
	listen/all.mk \
	process/all.mk \
	modules/all.mk \
	bin/all.mk

#
#  The default is to just build the source code.  We skip running the
#  test framework if it's not necessary.
#
ifneq "$(findstring test,$(MAKECMDGOALS))$(findstring clean,$(MAKECMDGOALS))" ""
SUBMAKEFILES +=	tests/all.mk
endif

#
#  Define a function to do all of the same thing.
#
ifneq "$(ENABLED_LANGUAGES)" ""
define ENABLE_LANGUAGE
language/${1}/all.mk:
	$${Q}echo "ENABLE LANGUAGE ${1}"

SUBMAKEFILES += language/${1}/all.mk
endef

$(foreach L,${ENABLED_LANGUAGES_LIST},$(eval $(call ENABLE_LANGUAGE,${L})))
endif
