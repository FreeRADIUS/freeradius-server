TARGET      =  rlm_perl.a
SOURCES        = rlm_perl.c

SRC_CFLAGS  = `perl -MExtUtils::Embed -e ccopts`
TGT_LDLIBS    = `perl -MExtUtils::Embed -e ldopts`
