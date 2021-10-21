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
