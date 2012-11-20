install: $(R)$(bindir)/checkrad

$(R)$(bindir)/checkrad: src/main/checkrad install.bindir
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
