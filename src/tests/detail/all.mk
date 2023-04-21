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
#	The server is reading and consuming the input detail file,
# 	so we copy it manually to the output directory (always), and then
#	put the server logs into the output file.
#
$(OUTPUT)/%: $(DIR)/% $(addprefix ${BUILD_DIR}/lib/,proto_detail.la proto_detail_file.la proto_detail_work.la)
	$(eval DIR := $(dir $<))
	${Q}echo "DETAIL $(notdir $<)"
	${Q}cp $< $(dir $@)/detail.txt
	${Q}if ! $(TEST_BIN)/radiusd -d $(DIR)/config -D ${top_srcdir}/share/dictionary -X > $@.log; then \
		tail $@.log; \
		echo "cp $< $(dir $@)/detail.txt; $(TEST_BIN)/radiusd -d $(DIR)/config -D ${top_srcdir}/share/dictionary -X "; \
		exit 1; \
	fi
	${Q}touch $@

.NO_PARALLEL: $(TEST)
$(TEST):
	@touch $(BUILD_DIR)/tests/$@
