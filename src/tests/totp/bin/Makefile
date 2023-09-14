#
#  TOTP isn't simple, so we need test cases.
#
all: totp

include ../../../../Make.inc

#
#  You can watch what it's doing by:
#
#	$ VERBOSE=1 make ... args ...
#
ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif

#
#  Hack up stuff so we can build in a subdirectory.
#
.PHONY: src
src:
	$(Q)ln -sf $(top_srcdir)/src

.PHONY: freeradius-devel
freeradius-devel:
	$(Q)ln -sf $(top_srcdir)/src/include freeradius-devel

#
#  ./totp decode <base32>
#
#  ./totp totp <time> <sha1key> <8-character-challenge>
#
totp: totp.c | src freeradius-devel
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(LDFLAGS) $(LIBS) \
			$(top_srcdir)/build/lib/.libs/libfreeradius-util.a \
			$(top_srcdir)/build/lib/.libs/libfreeradius-totp.a \
			totp.c

#
#  Test vectors from RFC 6238, Appendix B
#
test: totp
	$(Q)while IFS= read -r line; do \
		./totp totp $$line || exit 1; \
	done < sha1.txt

.PHONY: clean
clean:
	$(Q)rm -f *~ totp src freeradius-devel
