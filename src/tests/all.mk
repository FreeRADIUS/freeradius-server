#
#  The tests do a lot of rooting through files, which slows down non-test builds.
#
#  Therefore only include the test subdirectories if we're running the tests.
#  Or, if we're trying to clean things up.
#
ifneq "$(findstring test,$(MAKECMDGOALS))$(findstring clean,$(MAKECMDGOALS))" ""
SUBMAKEFILES := radmin/all.mk rbmonkey.mk eapol_test/all.mk dict/all.mk trie/all.mk unit/all.mk map/all.mk xlat/all.mk keywords/all.mk util/all.mk auth/all.mk modules/all.mk bin/all.mk daemon/all.mk
endif

#
#  Include all of the autoconf definitions into the Make variable space
#
-include $(BUILD_DIR)/tests/autoconf.h.mk

.PHONY: $(BUILD_DIR)/tests
$(BUILD_DIR)/tests:
	@mkdir -p $@

#
#  Pull all of the autoconf stuff into here.
#
$(BUILD_DIR)/tests/autoconf.h.mk: src/include/autoconf.h | $(BUILD_DIR)/tests
	${Q}grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@
