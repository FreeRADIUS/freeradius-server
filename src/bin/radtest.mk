install: $(R)$(bindir)/radtest

$(R)$(bindir)/radtest: src/bin/radtest | $(R)$(bindir)
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
