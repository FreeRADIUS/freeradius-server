# add this dependency BEFORE including the other submakefiles.
all: ${BUILD_DIR}/make/include/freeradius-devel

#TARGET	:= src/freeradius-devel

# Ensure that the devel files have access to radpaths.h
${BUILD_DIR}/make/include/freeradius-devel: src/include/radpaths.h
	[ -e $@ ] || (mkdir -p $(dir $@) && ln -s ${top_builddir}/src/include $@)

SUBMAKEFILES := include/all.mk lib/all.mk modules/all.mk main/all.mk

