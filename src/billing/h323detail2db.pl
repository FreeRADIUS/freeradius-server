#!/usr/bin/perl
#
# Author:       Peter Nixon <codemonkey@peternixon.net>
# Date:         August 2002 
# Summary:      Extract information from Radius detail log and
#		compare/insert/update a Postgresql database.
# Copy Policy:  GNU Public Licence Version 2 or later
# URL:          http://www.peternixon.net/code/
# Supported:    PostgreSQL (tested on version 7.2 and 7.3) and FreeRadius
# Copyright:    2002, 2003 Peter Nixon <codemonkey@petenixon.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# $Id$
#



# Modules that we use to get things done.
require DBI;
require Getopt::Long;

## Program and File locations
# gzcat - 'cat for .gz / gzip files' 
# If you don't have gzcat and do have gzip then use: ln gzip gzcat
$GZCAT = "/usr/bin/zcat";
# zcat - 'cat for .Z / compressed files'
$ZCAT = "/usr/bin/zcat";
# bzcat - 'cat for .bz2 files'
$BZCAT = "/usr/bin/bzcat";


# Default Variables
$database    = "radius";
$port        = "3306";
$user        = "postgres";
$password    = "";



#### You should not have to modify anything below here
$progname = "H323 Detail 2 DB";
$version = 1.01;

# Set up some basic variables
$passno = 0; $double_match_no = 0;

sub read_record {
	my $keepreading = 1;
	@record = ();
	while ($keepreading) {
		$_ = <DETAIL>;
		print "$_" if (&debug_get());
		if ( /^$/ ) {
			$keepreading = 0;
		} else {
			$record[++$#record] = $_;
		}
	}
}

sub db_connect {
	my $hostname = shift;
	if (&debug_get()) { print "DEBUG: Connecting to Database Host: $hostname\n" }
	if ($hostname eq 'localhost') {
	if (&debug_get()) { print "DEBUG: localhost connection so using UNIX socket instead of network socket.\n" }
		$dbh = DBI->connect("DBI:Pg:dbname=$database", "$user", "$password")
        	        or die "Couldn't connect to database: " . DBI->errstr;
	}
	else {
		$dbh = DBI->connect("DBI:Pg:dbname=$database;host=$hostname", "$user", "$password")
        	        or die "Couldn't connect to database: " . DBI->errstr;
	}
}

sub db_disconnect {
	### Now, disconnect from the database
	if (&debug_get()) { print "DEBUG: Disconnecting from Database Host: $hostname\n" }
	$dbh->disconnect
	    or warn "Disconnection failed: $DBI::errstr\n";
}

sub db_insert {
	print " Seconds: $AcctSessionTime  ";
	if ($h323_call_type eq 'VoIP') { 
        $sth2 = $dbh->prepare("INSERT into Stop$h323_call_type (RadiusServerName, AcctSessionId, AcctUniqueId,
		UserName, Realm, NASIPAddress, NASPortType, AcctSessionTime, AcctAuthentic, ConnectInfo_start,
		ConnectInfo_stop, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
		AcctTerminateCause, ServiceType, FramedProtocol, AcctStartDelay, AcctStopDelay,
		H323RemoteAddress, AcctStatusType, CiscoNASPort, h323calltype, h323callorigin, h323confid,
		h323connecttime, h323disconnectcause, h323disconnecttime, h323gwid, h323setuptime)
		values('girne-rad1', '$AcctSessionId', '', '$UserName', '', '$NasIPAddress', '$NasPortType',
		'$AcctSessionTime', '', '', '$ConnectInfo', '$AcctInputOctets', '$AcctOutputOctets',
		'$Called_Station_Id', '', '$AcctTerminateCause', '$ServiceType', '$FramedProtocol',
		'0', '$AcctDelayTime', '$h323_remote_address', 'Stop', '$Cisco_NAS_Port',
		'$h323_call_type', '', '$h323_conf_id', '$h323_connect_time', '$h323_disconnect_cause',
		'$h323_disconnect_time', '$h323_gw_id', '$h323_setup_time')");
	}
	elsif ($h323_call_type eq 'Telephony') {
        $sth2 = $dbh->prepare("INSERT into Stop$h323_call_type (RadiusServerName, AcctSessionId, AcctUniqueId,
                UserName, Realm, NASIPAddress, NASPortType, AcctSessionTime, AcctAuthentic, ConnectInfo_start,
                ConnectInfo_stop, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
                AcctTerminateCause, ServiceType, FramedProtocol, AcctStartDelay, AcctStopDelay,
                AcctStatusType, CiscoNASPort, h323calltype, h323callorigin, h323confid,
                h323connecttime, h323disconnectcause, h323disconnecttime, h323gwid, h323setuptime)
                values('girne-rad1', '$AcctSessionId', '', '$UserName', '', '$NasIPAddress', '$NasPortType',
                '$AcctSessionTime', '', '', '$ConnectInfo', '$AcctInputOctets', '$AcctOutputOctets',
                '$Called_Station_Id', '', '$AcctTerminateCause', '$ServiceType', '$FramedProtocol',
                '0', '$AcctDelayTime', 'Stop', '$Cisco_NAS_Port',
                '$h323_call_type', '', '$h323_conf_id', '$h323_connect_time', '$h323_disconnect_cause',
                '$h323_disconnect_time', '$h323_gw_id', '$h323_setup_time')");
	} else { print "ERROR: Unsupported h323calltype \"$h323_call_type\"\n" }

	$sth2->execute();
	#my $returned_rows = $sth2->rows;
	print "added to DB\n";
	$sth2->finish();

}

## This sub can be used to update data in an existing database if you have some fields not in the Database.
sub db_update {
	my $sth2= $dbh->prepare("UPDATE radacct SET CalledStationId = '$Called_Station_Id', 
		AcctTerminateCause = '$AcctTerminateCause', H323RemoteAddress = '$h323_remote_address',
		AcctStatusType = '$AcctStatusType', h323confid = '$h323_conf_id', h323calltype = '$h323_call_type',
		CiscoNASPort = '$Cisco_NAS_Port', h323gwid = '$h323_gw_id', h323disconnectcause = '$h323_disconnect_cause',
		h323connecttime = '$h323_connect_time', h323disconnecttime = '$h323_disconnect_time',
		h323setuptime = '$h323_setup_time' WHERE AcctSessionId = '$AcctSessionId' AND UserName = '$UserName'
		AND NASIPAddress = '$NasIPAddress' AND h323confid = '$h323_conf_id'");
        $sth2->execute();
        my $returned_rows = $sth2->rows;
        print " $returned_rows record(s) updated\n";
        $sth2->finish();

}

sub db_read {
	$passno++;
        print "Record: $passno) Conf ID: $h323_conf_id   Setup Time: $h323_setup_time  Call Length: $AcctSessionTime   ";
	my $sth = $dbh->prepare("SELECT RadAcctId FROM Stop$h323_call_type
		WHERE h323SetupTime = '$h323_setup_time'
		AND NASIPAddress = '$NasIPAddress'
		AND h323confid = '$h323_conf_id'")
                or die "Couldn't prepare statement: " . $dbh->errstr;

          my @data;
          $sth->execute()             # Execute the query
            or die "Couldn't execute statement: " . $sth->errstr;
           my $returned_rows = $sth->rows;

          if ($sth->rows == 0) {
		&db_insert;
          } elsif ($sth->rows == 1) {
                print "Exists in DB.\n";
		# FIXME: Make updates an option!
                #while (@data = $sth->fetchrow_array()) {
                #my $dbAcctSessionId = $data[1];
		##&db_update;
                #}
          } else {
		$double_match_no++;
		# FIXME: Log this somewhere!
                print "********* More than One Match! We have a problem!\n";
          }

        $sth->finish;

}

sub process_record {
	if (&debug_get()) { print "DEBUG: Processing Record\n"; }
	# Clear the variable we use.
	$AcctSessionId = ""; $UserName = ""; $NasPort=""; $NasPortType="";
	$NasIPAddress = ""; $AcctStatusType=""; $AcctSessionTime="";
	$AcctInputOctets=""; $AcctOutputOctets=""; $AcctTerminateCause="";
	$ServiceType=""; $FramedProtocol=""; $FramedIPAddress="";
	$Timestamp=""; $AcctDelayTime=""; $ConnectInfo=""; $Called_Station_Id="";
	$SQL_User_Name=""; $Cisco_NAS_Port=""; $Client_IP_Address="";
	$h323_remote_address=""; $h323_disconnect_cause=""; $h323_gw_id="";
	$h323_conf_id=""; $h323_call_type=""; $h323_disconnect_time="";
	$h323_connect_time=""; $h323_setup_time="";

	foreach (@record) {  		# Collect data

	# Initial cleanup of junk from the line of data
	s/^\s+//;	# Strip leading spaces.
    	chomp;		# Strip trailing CR

	# Parse the line of data into variables.
	$AcctStatusType = $_ if s/Acct-Status-Type = //;

	# All the data we need is in Stop records.
	return if ($AcctStatusType eq "Start");
	return if ($AcctStatusType eq "Alive");

	$AcctSessionId = $_ if s/Acct-Session-Id = //;
	$SQL_User_Name = $_ if s/SQL-User-Name = //;
	$UserName = $_ if s/User-Name = //;
	$NasPort = $_ if s/NAS-Port = //;
	$NasPortType = $_ if s/NAS-Port-Type = //;
	$NasIPAddress = $_ if s/NAS-IP-Address = //;
	$AcctSessionTime = $_ if s/Acct-Session-Time = //;
	$AcctInputOctets = $_ if s/Acct-Input-Octets = //;
	$AcctOutputOctets = $_ if s/Acct-Output-Octets = //;
	$AcctTerminateCause = $_ if s/Acct-Terminate-Cause = //;
	$AcctDelayTime = $_ if s/Acct-Delay-Time = //;
	$ServiceType = $_ if s/Service-Type = //;
	$FramedProtocol = $_ if s/Framed-Protocol = //;
	$FramedIPAddress = $_ if s/Framed-IP-Address = //;
	$FramedIPAddress = $_ if s/Framed-Address = //;
	$Timestamp = $_ if s/Timestamp = //;
	$ConnectInfo = $_ if s/Connect-Info = //;
	$Called_Station_Id = $_ if s/Called-Station-Id = //;
	$Cisco_NAS_Port = $_ if s/Cisco-NAS-Port = //;
	$Client_IP_Address = $_ if s/Client-IP-Address = //;
	if (s/h323-remote-address = \"h323-remote-address=//) {
			$h323_remote_address = $_;
		} elsif (s/h323-remote-address = //) {
			$h323_remote_address = $_;
	    };
	if (s/h323-disconnect-cause = \"h323-disconnect-cause=//) {
                        $h323_disconnect_cause = $_;
                } elsif (s/h323-disconnect-cause = //) {
                        $h323_disconnect_cause = $_;
            };
	if (s/h323-gw-id = \"h323-gw-id=//) {
                        $h323_gw_id = $_;
                } elsif (s/h323-gw-id = //) {
                        $h323_gw_id = $_;
            };
	if (s/h323-conf-id = \"h323-conf-id=//) {
                        $h323_conf_id = substr($_, 0, -1);
                } elsif (s/h323-conf-id = //) {
                        $h323_conf_id = $_;
            };
	if (s/h323-call-type = \"h323-call-type=//) {
                        $h323_call_type = substr($_, 0, -1);
                } elsif (s/h323-call-type = //) {
                        $h323_call_type = $_;
            };
	if (s/h323-connect-time = \"h323-connect-time=//) {
                        $h323_connect_time = substr($_, 0, -1);
                } elsif (s/h323-connect-time = //) {
                        $h323_connect_time = $_;
            };
	if (s/h323-disconnect-time = \"h323-disconnect-time=//) {
                        $h323_disconnect_time = substr($_, 0, -1);
                } elsif (s/h323-disconnect-time = //) {
                        $h323_disconnect_time = $_;
            };
	if (s/h323-setup-time = \"h323-setup-time=//) {
                        $h323_setup_time = substr($_, 0, -1);
                } elsif (s/h323-setup-time = //) {
                        $h323_setup_time = $_;
            };
                # FIXME: ugh, definitely look into using backreference.
                # something like s/(\S+)\s*=\s*\1/\1 = / or so
	  }


	# Remove quotation marks from a bunch of different fields (Stupid Cisco)
	$UserName =~ s/\"//g;
	$AcctSessionId =~ s/\"//g;
	$ConnectInfo =~ s/\"//g;
	$h323_remote_address =~ s/\"//g;
	$Called_Station_Id =~ s/\"//g;
	$h323_disconnect_cause =~ s/\"//g;
	$h323_setup_time =~ s/\"//g;
	$h323_connect_time =~ s/\"//g;
	$h323_disconnect_time =~ s/\"//g;
	$h323_conf_id =~ s/\"//g;
	$SQL_User_Name =~ s/\"//g;
	$h323_call_type =~ s/\"//g;
	$h323_gw_id =~ s/\"//g;

	# Remove Remove . from the start of time fields (routers that have lost ntp timesync temporarily)
	$h323_setup_time =~ s/^\.*//;
	$h323_connect_time =~ s/^\.*//;
	$h323_disconnect_time =~ s/^\.*//;

	# If its a valid record continue onto the database functions
	# FIXME: More checks needed here.
	if ($h323_call_type) { &db_read };
}

sub read_detailfile {
	my $filename = shift; my @record = ();
	if (&debug_get()) { print "DEBUG: Reading detail file: $filename\n" }
	if ( $filename =~ /.gz$/ ) {
		open (DETAIL, "$GZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} elsif ( $filename =~ /.Z$/ ) {
		open (DETAIL, "$ZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} elsif ( $filename =~ /.bz2$/ ) {
		open (DETAIL, "$BZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} else {
		open (DETAIL, "<$filename") || warn "read_detailfile(\"$filename\"): $!\n";
	}
	$valid_input = (eof(DETAIL) ? 0 : 1);
	if (&debug_get()) { print "DEBUG: Reading records\n"; }
	while($valid_input) {
		$valid_input = 0 if (eof(DETAIL));
		if (&debug_get()) { print "DEBUG: -Reading Record-\n"; }
		&read_record;
		print "DEBUG: $AcctSessionId" if (&debug_get());
		&process_record;
	}
}

sub print_usage_info {
	print "\n";
	$leader = "$progname $version Usage Information";
	$underbar = $leader;
	$underbar =~ s/./-/g;
	print "$leader\n$underbar\n";
	print "\n";
	print "  Syntax:   h323detail2db.pl [ options ]\n";
	print "\n";
	print "    -h --help                        Show this usage information\n";
	print "    -x --debug                       Turn on debugging\n";
	print "    -V --version                     Show version and copyright\n";
	print "    -H --host                        Database host to connect to (Default: localhost)\n";
	print "    -f --file <detailfile>           Detail file\n";
	print "\n";
}

# Get debugging state
sub debug_get() {
	return $debug;
}

# Set debugging state
sub debug_set($) {
	$debug = $_[0];
}


sub main {
        # Parse the command line for options
        if (!scalar(@ARGV)) {
        	&print_usage_info();
		exit(SUCCESS);
	};

	# See the Getopt::Long man page for details on the syntax of this line
	@valid_opts = ("h|help", "V|version", "f|file=s", "x|v|debug", "D|date=s", "H|host=s");
	Getopt::Long::Configure("no_getopt_compat", "bundling", "no_ignore_case");
	Getopt::Long::GetOptions(@valid_opts);

	# Post-parse the options stuff
	select STDOUT; $| = 1;
	if ($opt_V) {
		# Do not edit this variable.  It is updated automatically by CVS when you commit
		my $rcs_info = 'CVS Revision $Revision$ created on $Date$ by $Author$ ';

		$rcs_info =~ s/\$\s*Revision: (\S+) \$/$1/;
		$rcs_info =~ s/\$\s*Date: (\S+) (\S+) \$/$1 at $2/;
		$rcs_info =~ s/\$\s*Author: (\S+) \$ /$1/;

		print "\n";
		print "$progname Version $version by Peter Nixon <codemonkey\@peternixon.net>\n";
		print "Copyright (c) 2002-2003, 2003 Peter Nixon\n";
		print "  ($rcs_info)\n";
		print "\n";
		return SUCCESS;
	} elsif ($opt_h) {
	        &print_usage_info();
	        exit(SUCCESS);
	}

	&debug_set($opt_x);

	if ($opt_f) {
		if ($opt_H) { &db_connect($opt_H);
		} else { &db_connect(localhost); }

		&read_detailfile($opt_f);

		&db_disconnect;
	} else {
		print "You didn't specify a detail file.\n";
		exit(FAILURE);
	}

}


exit &main();
