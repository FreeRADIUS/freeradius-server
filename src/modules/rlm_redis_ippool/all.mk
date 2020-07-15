SUBMAKEFILES := rlm_redis_ippool.mk rlm_redis_ippool_tool.mk

LUA_SCRIPTS = preamble alloc release update

install: $(foreach f,$(LUA_SCRIPTS),$(R)$(modconfdir)/redis_ippool/$(f).lua)

$(R)$(modconfdir)/%: raddb/mods-config/mods-config/%
	@$(ECHO) INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(@D)
