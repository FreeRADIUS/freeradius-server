SUBMAKEFILES := rbmonkey.mk unit/all.mk map/all.mk xlat/all.mk keywords/all.mk auth/all.mk modules/all.mk

#
#  Include all of the autoconf definitions into the Make variable space
#
-include $(BUILD_DIR)/tests/keywords/autoconf.h.mk

#
#  Pull all of the autoconf stuff into here.
#
$(BUILD_DIR)/tests/keywords/autoconf.h.mk: src/include/autoconf.h
	@grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@
