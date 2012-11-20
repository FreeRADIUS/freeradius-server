install: $(R)$(bindir)/radzap

$(R)$(bindir)/radzap: install.bindir src/main/radzap
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(bindir)
