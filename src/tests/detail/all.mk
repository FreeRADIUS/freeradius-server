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
#  The test loads modules at run time, so make needs telling about them.  The
#  list comes from the config itself.
#
$(eval $(call TEST_CONFIG_LIBS,$(DIR)/config/radiusd.conf,$(FILES.$(TEST))))

#
#	The server is reading and consuming the input detail file,
# 	so we copy it manually to the output directory (always), and then
#	put the server logs into the output file.
#
DETAIL_COPY_CMD = \
	cp \
	$(call SHELL_QUOTE,$<) \
	$(call SHELL_QUOTE,$(dir $@)detail.txt)

DETAIL_CMD = \
	$(TEST_BIN)/radiusd \
	-d $(call SHELL_QUOTE,$(dir $<)config) \
	-D ${top_srcdir}/share/dictionary \
	-X

$(OUTPUT)/%: $(DIR)/% $(addprefix ${BUILD_DIR}/lib/,proto_detail.la proto_detail_file.la proto_detail_work.la)
	${Q}echo "DETAIL $(notdir $<)"
	${Q}$(DETAIL_COPY_CMD)
	${Q}rm -f $(dir $@)/processed
	${Q}if ! $(DETAIL_CMD) > $@.log; then \
		tail $@.log; \
		echo $(call SHELL_QUOTE,$(DETAIL_COPY_CMD)); \
		echo $(call SHELL_QUOTE,$(DETAIL_CMD)); \
		exit 1; \
	fi
	${Q}if [ ! -e $(dir $@)/processed ] ; then \
		tail $@.log; \
		echo "Processing $< failed to produce expected output $(dir $@)/processed"; \
		exit 1; \
	fi
	${Q}touch $@

$(TEST):
	@touch $(BUILD_DIR)/tests/$@
