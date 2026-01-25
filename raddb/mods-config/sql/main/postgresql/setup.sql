--
-- setup.sql -- PostgreSQL commands for creating the RADIUS user.
--
--	WARNING: You should change 'localhost' and 'radpass'
--		 to something else.  Also update mods-available/sql
--		 with the new RADIUS password.
--
--	WARNING: This example file is untested.  Use at your own risk.
--		 Please send any bug fixes to the mailing list.
--
--	$Id$
--

--
--  Create default administrator for RADIUS
--
CREATE USER radius WITH PASSWORD 'radpass';

--
--  The server can read the authorisation data
--
GRANT SELECT ON radcheck TO radius;
GRANT SELECT ON radreply TO radius;
GRANT SELECT ON radusergroup TO radius;
GRANT SELECT ON radgroupcheck TO radius;
GRANT SELECT ON radgroupreply TO radius;

--
--  The server can write accounting and post-auth data
--
GRANT SELECT, INSERT, UPDATE on radacct TO radius;
GRANT SELECT, INSERT, UPDATE on radpostauth TO radius;

--
--  The server can read the NAS data
--
GRANT SELECT ON nas TO radius;

--
--  In the case of the "lightweight accounting-on/off" strategy, the server also
--  records NAS reload times
--
GRANT SELECT, INSERT, UPDATE ON nasreload TO radius;

--
--  Grant permissions on sequences
--
GRANT USAGE, SELECT ON SEQUENCE radcheck_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radreply_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radusergroup_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radgroupcheck_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radgroupreply_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radacct_radacctid_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE radpostauth_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE nas_id_seq TO radius;
