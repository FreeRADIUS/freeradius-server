#
#  TOTP isn't simple, so we need test cases.
#
all: totp

include ../../../Make.inc

#
#  Hack up stuff so we can build in a subdirectory.
#
.PHONY: src
src:
	@ln -sf ../../../src

.PHONY: freeradius-devel
freeradius-devel:
	@ln -sf ../../../src/include freeradius-devel

#
#  ./totp decode <base32>
#
#  ./totp totp <time> <sha1key> <8-character-challenge>
#
totp: rlm_totp.c | src freeradius-devel
	@$(CC) -DTESTING $(CFLAGS) $(CPPFLAGS) $(OPENSSL_CPPFLAGS) -o $@ $(LDFLAGS) $(LIBS) ../../../build/lib/.libs/libfreeradius-radius.a rlm_totp.c

#
#  Test vectors from RFC 6238, Appendix B
#
test: totp
	@while IFS= read -r line; do \
		./totp totp $$line || exit 1; \
	done < sha1.txt
