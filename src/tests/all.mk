SUBMAKEFILES := rbmonkey.mk eapol_test/all.mk dict/all.mk trie/all.mk unit/all.mk map/all.mk xlat/all.mk keywords/all.mk util/all.mk auth/all.mk modules/all.mk daemon/all.mk 

#
#  Include all of the autoconf definitions into the Make variable space
#
-include $(BUILD_DIR)/tests/keywords/autoconf.h.mk

#
#  Pull all of the autoconf stuff into here.
#
$(BUILD_DIR)/tests/keywords/autoconf.h.mk: src/include/autoconf.h
	${Q}grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@
