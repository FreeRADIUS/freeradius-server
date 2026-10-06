#
#  CFLAGS are tuned for callgrind:
#    -g3                          full debug info for symbol resolution
#    -O1                          realistic hotspot costs without losing structure
#    -fno-omit-frame-pointer      keep frame pointers so callgrind can stack-walk
#    -fno-inline + -Dalways_inline=
#                                 preserve call edges; -fno-inline alone leaves
#                                 CC_HINT(flatten) and the always_inline attribute
#                                 to still erase them
#    -fno-optimize-sibling-calls  suppress tail-call elimination
#    -fno-plt                     cross-library calls go through the GOT instead
#                                 of PLT stubs, which lack DWARF info
#    -fno-builtin                 keep stdlib helpers (memcpy, strlen, ...) visible
#                                 instead of having them inlined as builtins
#

# CFLAGS and LDFLAGS env variables. Setting these env variables allows
# us to then use them in various profiling statistic scripts for logging.
ENV PROFILING_CFLAGS="-g3 -O1 -fno-omit-frame-pointer -fno-inline -Dalways_inline= -fno-optimize-sibling-calls -fno-plt -fno-builtin"
ENV PROFILING_LDFLAGS="-fno-omit-frame-pointer"

define(`RADENV_CONFIGURE_ARGS', `        --disable-verify-ptr \
        CFLAGS="$PROFILING_CFLAGS" \
        LDFLAGS="$PROFILING_LDFLAGS" \
')dnl
