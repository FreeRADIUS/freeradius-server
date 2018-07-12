install: $(R)$(bindir)/radzap

$(R)$(bindir)/radzap: src/main/radzap | $(R)$(bindir)
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
