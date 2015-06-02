Module Tests
------------

To test module `foo`, create a directory `foo`, and put a file `all.mk` into it, e.g.

    foo/all.mk

All of the tests for the module should go here.  The tests will be run
*only* if the module is available, and has been built correctly on the system.

The file should contain a target "MODULE.test".  This is the main
target used to test the module.  The framework automatically makes the
tests depend on the module (i.e. library).  So if the module source
changes, you can just do `make MODULE.test`.  The module will be
re-built, and the tests will be run.

Note: all SQL tests share the same tests definitions (see sql directory).
The modules themselves simply link to the actual tests files.
