install: $(R)$(bindir)/radlast

$(R)$(bindir)/radlast: src/main/radlast install.bindir
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
