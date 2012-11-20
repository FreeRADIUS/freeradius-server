install: install.radzap

.PHONY: install.radzap

install.radzap:
	@echo INSTALL radzap
	@$(INSTALL) -m 755 src/main/radzap $(R)$(bindir)