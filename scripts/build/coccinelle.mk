#
#  Include coccinelle targets, to test or apply semantic patches
#  found in build/coccinelle.
#
ifeq ($(shell which spatch 2> /dev/null),)
.PHONY: coccinelle coccinelle.help
coccinelle coccinelle.help:
	@echo "coccinelle requires 'spatch' to be installed."
else

#
#  Coccinelle default command arguments
#
SPATCH_BIN  := spatch
SPATCH_ARGS := --tmp-dir $(BUILD_DIR)
OUTPUT      := $(BUILD_DIR)/coccinelle
FILES       := $(subst scripts/,build/,$(wildcard scripts/coccinelle/*.cocci))

#
#  This Makefile is included in-line, and not via the "boilermake"
#  wrapper.  But it's still useful to use the same process for
#  seeing commands that are run.
#
ifeq "${VERBOSE}" ""
	Q=@
	SPATCH_ARGS += --very-quiet
else
	Q=
endif

$(OUTPUT)/%.cocci: scripts/coccinelle/%.cocci
	@echo "COCCINELLE-${SPATCH_MODE} $<"
	$(if $(filter ${SPATCH_MODE},PATCH),$(eval SPATCH_ARGS+= --in-place))
	$(eval SPATCH_RUN := $(SPATCH_BIN) $(SPATCH_ARGS) --cocci-file $< --dir src)
	$(Q)mkdir -p $(dir $@)
	${Q}if ! $(SPATCH_RUN) 2>&1; then \
		echo "Problems to execute: $(SPATCH_RUN)"; \
		exit 1;\
	fi
	${Q}touch $@

#
#  Enter here: This builds everything
#
.PHONY: coccinelle coccinelle.help
coccinelle: coccinelle.help

#
#  Dump out some useful information on what Coccinelle option should be called.
#
coccinelle.help:
	@echo ""
	@echo "Make targets:"
	@echo "    coccinelle.help    - Print this"
	@echo "    coccinelle.clean   - Clean up the $(OUTPUT)"
	@echo "    coccinelle.diff    - Print diffs for files which would be changed by coccinelle.patch"
	@echo "    coccinelle.patch   - Apply Coccinelle patches to all source files in the tree."

.PHONY: coccinelle.clean
coccinelle.clean:
	${Q}rm -rf $(OUTPUT)

.PHONY: coccinelle.diff
coccinelle.diff: SPATCH_MODE=DIFF
coccinelle.diff: $(FILES)

.PHONY: coccinelle.patch
coccinelle.patch: SPATCH_MODE=PATCH
coccinelle.patch: $(FILES)

endif
