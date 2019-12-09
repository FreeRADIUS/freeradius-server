#!/bin/sh

set -e

need_something=false

function ERROR
{
	echo "$@" 1>&2;
}

function INFO
{
	echo "$@"
}

bin=$1
shift

if ! which llvm-symbolizer > /dev/null; then
	ERROR "llvm-symbolizer must be in the current PATH ($PATH)"
	need_something=true
fi

if ! which pprof > /dev/null; then
	ERROR "pprof must be in the current PATH ($PATH).  If not installed \`brew install gperftools\`"
	need_something=true
fi

if ! which dot > /dev/null; then
	ERROR "dot must be in the current PATH ($PATH).  If not installed \`brew install gprof2dot\`"
	need_something=true
fi

if ! which ps2pdf > /dev/null; then
	ERROR "ps2pdf must be in the current PATH ($PATH).  If not installed \`brew install ghostscript\`"
	need_something=true
fi

if ! test -e "$bin"; then
	ERROR "Binary to profile \"$bin\" does not exist"
	need_something=true
fi

if ! $need_something && ! otool -L "$bin" | grep 'libprofiler' > /dev/null; then
	ERROR "$1 must be linked against libprofiler"
	ERROR "Either '-lprofiler' or \`brew install gperftools\` and rerun configure"
	need_something=true
fi

if $need_something; then
	exit 1
fi

: ${PROFILE_OUT:=$(mktemp /tmp/profile.XXXX)}
: ${PROFILE_PDF_OUT:=${PROFILE_OUT}.pdf}

# Call the binary
CPUPROFILE="$PROFILE_OUT" $bin $@

INFO "Profile written to \"$PROFILE_OUT\", override with PROFILE_OUT"

pprof --pdf "$bin" "$PROFILE_OUT" > "$PROFILE_PDF_OUT"

INFO "Profile analysis written to \"$PROFILE_PDF_OUT\", override with PROFILE_PDF_OUT"

if which open > /dev/null; then
	open "$PROFILE_PDF_OUT"
fi
