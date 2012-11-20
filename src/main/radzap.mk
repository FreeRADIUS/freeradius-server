install: $(R)$(bindir)/radzap

$(R)$(bindir)/radzap: src/main/radzap install.bindir
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
