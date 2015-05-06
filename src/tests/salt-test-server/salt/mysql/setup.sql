# -*- text -*-
##
## admin.sql -- MySQL commands for creating the RADIUS user.
##
##	WARNING: You should change 'localhost' and 'radpass'
##		 to something else.  Also update raddb/sql.conf
##		 with the new RADIUS password.
##
##	$Id$

#
#  Create default administrator for RADIUS
#
CREATE USER 'radius';
SET PASSWORD FOR 'radius' = PASSWORD('radpass');

# Need to read when running RADIUS and delete for cleanup
GRANT ALL ON radius.* TO 'radius';
