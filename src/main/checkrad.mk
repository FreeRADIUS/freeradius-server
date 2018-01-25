install: $(R)$(sbindir)/checkrad

$(R)$(sbindir)/checkrad: src/main/checkrad | $(R)$(sbindir)
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(sbindir)
