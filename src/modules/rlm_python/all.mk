TARGET     = rlm_python.a
SOURCES       = rlm_python.c

TGT_LDLIBS   = -L/System/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/config             		-ldl  -lpython2.6 -lm
SRC_CFLAGS = -I/System/Library/Frameworks/Python.framework/Versions/2.6/include/python2.6
