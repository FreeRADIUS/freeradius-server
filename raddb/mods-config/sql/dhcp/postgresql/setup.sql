/*
 * admin.sql -- PostgreSQL commands for creating the RADIUS user.
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
CREATE USER radius WITH PASSWORD 'radpass';

/*
 * The server can read any table in SQL
 */
GRANT SELECT ON dhcpreply TO radius;
GRANT SELECT ON dhcpgroupreply TO radius;
GRANT SELECT ON dhcpgroup TO radius;

GRANT USAGE, SELECT ON SEQUENCE dhcpgroupreply_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE dhcpreply_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE dhcpgroup_id_seq TO radius;
