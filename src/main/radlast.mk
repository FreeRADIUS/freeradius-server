install: $(R)$(bindir)/radlast

$(R)$(bindir)/radlast: install.bindir src/main/radlast
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
