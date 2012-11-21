# add this dependency BEFORE including the other submakefiles.
all: ${BUILD_DIR}/make/include/freeradius-devel src/freeradius-devel

.PHONY: ${BUILD_DIR}/make/include/freeradius-devel
${BUILD_DIR}/make/include/freeradius-devel:
	@[ -e $@ ] || (mkdir -p $(dir $@) && ln -s ${top_builddir}/src/include $@)

.PHONY: src/freeradius-devel
src/freeradius-devel:
	@[ -e $@ ] || ln -s include $@

SUBMAKEFILES := include/all.mk lib/all.mk modules/all.mk main/all.mk

