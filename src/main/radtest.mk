install: $(R)$(bindir)/radtest

$(R)$(bindir)/radtest: src/main/radtest install.bindir
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
