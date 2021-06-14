# add this dependency BEFORE including the other submakefiles.
all:

SUBMAKEFILES := include/all.mk \
	lib/all.mk \
	protocols/all.mk \
	listen/all.mk \
	process/all.mk \
	modules/all.mk \
	bin/all.mk \
	tests/all.mk
