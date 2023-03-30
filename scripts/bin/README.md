# Wrapper scripts for binaries

The build process creates "local" versions of the binaries.  These
binaries can be run out of the source / build tree, and do not need to
be installed in order to work.

However, the "local" binaries require manual mangling of environment
variables in order to work.  As such, it's easier to just have shell
script wrappers so people have to remember fewer things.
