ifneq "$(findstring fuzzer,${CFLAGS})" ""
TARGET		:= fuzzer
SOURCES		:= fuzzer.c

TGT_INSTALLDIR  :=
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= libfreeradius-radius.a

fuzzer.run: $(BUILD_DIR)/bin/fuzzer
	${Q}./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer \
	-artifact_prefix=src/tests/fuzzer/ \
	-max_len=512 \
	-D share \
	src/tests/fuzzer

.PHONY: fuzzer.help
fuzzer.help:
	@echo ./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer -max_len=512 -D share src/tests/fuzzer

endif
