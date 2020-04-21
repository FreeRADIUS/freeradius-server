# add this dependency BEFORE including the other submakefiles.
all:

SUBMAKEFILES := include/all.mk \
	build/all.mk \
	lib/all.mk \
	bin/all.mk \
	protocols/all.mk \
	modules/all.mk \
	tests/all.mk
