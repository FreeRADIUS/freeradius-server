# add this dependency BEFORE including the other submakefiles.
all:

SUBMAKEFILES := $(filter-out %/freeradius-devel/all.mk,$(wildcard ${top_srcdir}/src/*/all.mk))
