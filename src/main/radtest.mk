install: $(R)$(bindir)/radtest

$(R)$(bindir)/radtest: install.bindir src/main/radtest
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
