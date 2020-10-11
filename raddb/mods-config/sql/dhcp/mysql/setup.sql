/*
 * setup.sql -- MySQL commands for creating the RADIUS user.
 *
 *	WARNING: You should change 'localhost' and 'radpass'
 *		 to something else.  Also update raddb/mods-available/sql
 *		 with the new RADIUS password.
 *
 *	WARNING: This example file is untested.  Use at your own risk.
 *		 Please send any bug fixes to the mailing list.
 *
 *	$Id$
 */

/*
 *  Create default administrator for RADIUS
 */
CREATE USER 'radius'@'localhost' IDENTIFIED BY 'radpass';

GRANT SELECT ON radius.dhcpreply TO 'radius'@'localhost';
GRANT SELECT ON radius.dhcpgroupreply TO 'radius'@'localhost';
GRANT SELECT ON radius.dhcpgroup TO 'radius'@'localhost';
