/* Default Database File Names */

#define RADIUS_DIR		RADDBDIR
#define RADACCT_DIR		RADIR
#define L_DST_DIR		LOGDIR

#define RADIUS_DICTIONARY	"dictionary"
#define RADIUS_CLIENTS		"clients"
#define RADIUS_NASLIST		"naslist"
#define RADIUS_REALMS		"realms"

#define RADUTMP			LOGDIR "/radutmp"
#define SRADUTMP		LOGDIR "/sradutmp"
#define RADWTMP			LOGDIR "/radwtmp"
#define SRADWTMP		LOGDIR "/sradwtmp"

#ifdef __APPLE__
#  define LT_SHREXT ".dylib"
#elif defined (WIN32)
#  define LT_SHREXT ".dll"
#else
#  define LT_SHREXT ".so"
#endif
