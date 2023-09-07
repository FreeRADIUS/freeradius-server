install: $(R)/$(bindir)/radsecret

$(R)/$(bindir)/radsecret: ${top_srcdir}/src/main/radsecret
	@$(ECHO) INSTALL radsecret
	$(Q)${PROGRAM_INSTALL} -c -m 755 $< $@
