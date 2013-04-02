#ifndef SQL_CONF_H
#define SQL_CONF_H
/***************************************************************************
*  conf.h			     rlm_sql - FreeRADIUS SQL Module      *
*									  *
*      Configuration options for the SQL module			    *
*									  *
*				     Mike Machado <mike@innercite.com>    *
***************************************************************************/

RCSIDH(conf_h, "$Id$")

#define CHECKRAD1		"/usr/sbin/checkrad"
#define CHECKRAD2		"/usr/local/sbin/checkrad"

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
    WARNING: This hack works for me, but I only have one PRI!!!  I've not
	tested it on 2 or more (or with models other than the Max 4048)
    Use at your own risk!
  -- dgreer@austintx.com
*/

#define ASCEND_PORT_HACK
#define ASCEND_CHANNELS_PER_LINE	23

/* SQL defines */
#define MAX_QUERY_LEN			4096
#define SQL_LOCK_LEN			MAX_QUERY_LEN
#define	SQLTRACEFILE			RADLOG_DIR "/sqltrace.sql"

/* SQL Errors */
#define SQL_DOWN			1 /* for re-connect */

#define MAX_COMMUNITY_LEN		50
#define MAX_TABLE_LEN			20
#define MAX_AUTH_QUERY_LEN		256
#define AUTH_STRING_LEN			128

#endif /* SQL_CONF_H */
