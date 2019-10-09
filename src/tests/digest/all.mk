#
#	Unit tests for digest against the radiusd.
#

#
#	Test name
#
TEST  := test.digest
FILES := $(subst $(DIR)/%,,$(wildcard $(DIR)/*.txt))
$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
RADCLIENT_BIN     := $(TESTBINDIR)/radclient
DIGEST_BUILD_DIR  := $(BUILD_DIR)/tests/digest
DIGEST_RADIUS_LOG := $(DIGEST_BUILD_DIR)/radiusd.log
DIGEST_GDB_LOG    := $(DIGEST_BUILD_DIR)/gdb.log
DIGEST_TEST_FILES := $(wildcard $(DIR)/*.txt)

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,digest,$(OUTPUT)))

#
#	Run the digest commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% test.digest.radiusd_kill test.digest.radiusd_start
	$(eval TARGET := $(patsubst %.txt,%,$(notdir $@)))
	${Q}for _num in $$(sed '/^#.*TESTS/!d; s/.*TESTS//g' $<); do \
		echo "DIGEST-TEST $(TARGET)_$${_num}";                   \
		cp -f $< $@.request;                                     \
		echo "Test-Name = \"$(TARGET)\"" >> $@.request;          \
		echo "Test-Number = \"$${_num}\"" >> $@.request;         \
		if ! $(RADCLIENT_BIN) -f $@.request -xF -d src/tests/digest/config -D share/dictionary 127.0.0.1:$(PORT) auth $(SECRET) > $@.out; then \
			echo "Problems with $(RADCLIENT_BIN) -f $@_request -xF -d src/tests/digest/config -D share/dictionary 127.0.0.1:$(PORT) auth $(SECRET)"; \
			cat $@.out;                                          \
			$(MAKE) test.digest.radiusd_kill;                    \
			exit 1;                                              \
		else                                                     \
			touch $@;                                            \
		fi;                                                      \
	done

$(TEST): $(FILES)
	${Q}$(MAKE) test.digest.radiusd_kill
