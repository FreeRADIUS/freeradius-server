TARGET := value_cast

SOURCES := value_cast.c

TGT_PREREQS := libfreeradius-radius.a
TGT_LDLIBS := $(LIBS)
TGT_INSTALLDIR :=

.PHONY: tests.value_cast
tests.value_cast: $(BUILD_DIR)/bin/value_cast
	${Q}$(JLIBTOOL) --quiet --mode=execute $<

tests.unit: tests.value_cast
