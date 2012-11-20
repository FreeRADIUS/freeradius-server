install: $(R)$(bindir)/checkrad

$(R)$(bindir)/checkrad: install.bindir src/main/checkrad
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
