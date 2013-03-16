/* Default Database File Names */

#define RADIUS_DIR		RADDBDIR
#define RADACCT_DIR		RADIR
#define RADLOG_DIR		LOGDIR

#define RADIUS_DICTIONARY	"dictionary"
#define RADIUS_CLIENTS		"clients"
#define RADIUS_NASLIST		"naslist"
#define RADIUS_REALMS		"realms"

#define RADUTMP			LOGDIR "/radutmp"
#define SRADUTMP		LOGDIR "/sradutmp"
#define RADWTMP			LOGDIR "/radwtmp"
#define SRADWTMP		LOGDIR "/sradwtmp"

/* Hack for funky ascend ports on MAX 4048 (and probably others)
   The "NAS-Port-Id" value is "xyyzz" where "x" = 1 for digital, 2 for analog;
   "yy" = line number (1 for first PRI/T1/E1, 2 for second, so on);
   "zz" = channel number (on the PRI or Channelized T1/E1).
    This should work with normal terminal servers, unless you have a TS with
	more than 9999 ports ;^).
    The "ASCEND_CHANNELS_PER_LINE" is the number of channels for each line into
	the unit.  For my US/PRI that's 23.  A US/T1 would be 24, and a
	European E1 would be 30 (I think ... never had one ;^).
    This will NOT change the "NAS-Port-Id" reported in the detail log.  This
	is simply to fix the dynamic IP assignments a la Cistron.
    You can change the default of 23 with an argument to ./configure.
    WARNING: This hack works for me, but I only have one PRI!!!  I've not
	tested it on 2 or more (or with models other than the Max 4048)
    Use at your own risk!
  -- dgreer@austintx.com
*/
#ifdef ASCEND_PORT_HACK
#  ifndef ASCEND_CHANNELS_PER_LINE
#    define ASCEND_CHANNELS_PER_LINE	23
#  endif
#endif
