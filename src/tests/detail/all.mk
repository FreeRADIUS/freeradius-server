#
#	Unit tests for the detail file reader.
#

#
#	Test name
#
TEST  := test.detail
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Run the radclient commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/%
	$(eval DIR := $(dir $<))
	${Q}echo "DETAIL $(notdir $<)"
	${Q}cp $< $(dir $@)/detail.txt
	${Q}if ! $(TEST_BIN)/radiusd -d $(DIR)/config -D ${top_srcdir}/share/dictionary -X > $@; then \
		tail $@; \
		echo "cp $< $(dir $@)/detail.txt; $(TEST_BIN)/radiusd -d $(DIR)/config -D ${top_srcdir}/share/dictionary -X "; \
		exit 1; \
	fi

.NO_PARALLEL: $(TEST)
$(TEST):
	@touch $(BUILD_DIR)/tests/$@
