install: $(R)$(sbindir)/rc.radiusd $(R)$(sbindir)/raddebug \
	$(R)$(bindir)/radsqlrelay $(R)$(bindir)/radcrypt $(R)$(bindir)/rlm_sqlippool_tool

$(R)$(sbindir)/rc.radiusd: scripts/rc.radiusd
	${Q}mkdir -p $(dir $@)
	${Q}$(INSTALL) -m 755 $< $@

$(R)$(sbindir)/raddebug: scripts/util/raddebug
	${Q}mkdir -p $(dir $@)
	${Q}$(INSTALL) -m 755 $< $@

$(R)$(bindir)/radsqlrelay: scripts/sql/radsqlrelay
	${Q}mkdir -p $(dir $@)
	${Q}$(INSTALL) -m 755 $< $@

$(R)$(bindir)/radcrypt: scripts/util/cryptpasswd
	${Q}mkdir -p $(dir $@)
	${Q}$(INSTALL) -m 755 $< $@

$(R)$(bindir)/rlm_sqlippool_tool: scripts/sql/rlm_sqlippool_tool
	${Q}mkdir -p $(dir $@)
	${Q}$(INSTALL) -m 755 $< $@

#
#  The "coverage" target
#
ifneq "$(findstring coverage,$(MAKECMDGOALS))" ""
include scripts/build/coverage.mk
endif

#
#  The "coccinelle" target
#
ifneq "$(findstring coccinelle,$(MAKECMDGOALS))" ""
include scripts/build/coccinelle.mk
endif

#
#  The "log_id" target
#
ifneq "$(findstring logid,$(MAKECMDGOALS))" ""
include scripts/build/logid.mk
endif
