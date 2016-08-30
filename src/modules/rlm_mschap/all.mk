SUBMAKEFILES := rlm_mschap.mk smbencrypt.mk

src/modules/rlm_mschap/rlm_mschap.mk: src/modules/rlm_mschap/rlm_mschap.mk.in src/modules/rlm_mschap/configure
	${Q}echo CONFIGURE $(dir $<)
	${Q}cd $(dir $<) && ./configure $(CONFIGURE_ARGS)
