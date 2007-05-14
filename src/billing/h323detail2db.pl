#!/usr/bin/perl
#
# Author:       Peter Nixon <codemonkey@peternixon.net>
# Summary:      Extract information from Radius detail log and
#		compare/insert/update a Postgresql database.
# Copy Policy:  GNU Public Licence Version 2
# URL:          http://www.peternixon.net/code/
# Supported:    PostgreSQL (tested on version 7.2, 7.3, 7.4 and 8) and FreeRadius
# Copyright:    2004 Peter Nixon http://www.petenixon.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of Version 2 of the GNU General Public License as
# published by the Free Software Foundation.
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
$progname = "H323 Detail2DB";
$version = 2.2;

# Set up some basic variables
my $passno = 0; my $duplicates = 0; my $verbose = 0; my %duplicate_records = ();
my $starttime = time();


sub db_connect {
	my $hostname = shift;
	if ($verbose > 1) { print "DEBUG: Connecting to Database Host: $hostname\n" }
	if ($hostname eq 'localhost') {
	if ($verbose > 1) { print "DEBUG: localhost connection so using UNIX socket instead of network socket.\n" }
		$dbh = DBI->connect("DBI:Pg:dbname=$database", "$user", "$password")
        	        or die "Couldn't connect to database: " . DBI->errstr;
	} else {
		$dbh = DBI->connect("DBI:Pg:dbname=$database;host=$hostname", "$user", "$password")
        	        or die "Couldn't connect to database: " . DBI->errstr;
	}
}

sub db_disconnect {
	my $hostname = shift;
	if ($verbose > 1) { print "DEBUG: Disconnecting from Database Host: $hostname\n" }
	$dbh->disconnect		# Disconnect from the database
	    or warn "Disconnection failed: $DBI::errstr\n";
}

sub process_duplicates {
	if ($verbose > 1) { print "DEBUG: Now processing $duplicates duplicate records\n" }
	foreach my $a1 ( keys %duplicate_records ) {
		print "$a1:\n";
		for my $a2 ( keys %{ $duplicate_records{$a1} } ) {
			print "\t$a2 = $duplicate_records{$a1}{$a2}\n";
		}
	print "\n";
	}
}


sub procedure_insert {		# FIXME: Does not work with current SQL schema. Use standard method
	if ($verbose > 0) { print "Record: $passno) Conf ID: $h323_conf_id   Setup Time: $h323_setup_time  Call Length: $AcctSessionTime   "; }
	if ($h323_call_type eq 'VoIP') {
        $sth2 = $dbh->prepare("SELECT VoIPInsertRecord('$UserName', '$NasIPAddress', '$AcctSessionTime', '$AcctInputOctets', '$AcctOutputOctets',
		'$Called_Station_Id', '$Calling_Station_Id', '$AcctDelayTime', '$h323_call_origin', '$h323_setup_time',
		'$h323_connect_time','$h323_disconnect_time', '$h323_disconnect_cause', (NULLIF('$h323_remote_address', '')::inet), '$h323_voice_quality', '$h323_conf_id')");
	}
	elsif ($h323_call_type eq 'Telephony') {
        $sth2 = $dbh->prepare("SELECT TelephonyInsertRecord('$UserName', '$NasIPAddress', '$AcctSessionTime', '$AcctInputOctets', '$AcctOutputOctets',
		'$Called_Station_Id', '$Calling_Station_Id', '$AcctDelayTime', '$Cisco_NAS_Port', '$h323_call_origin',
		'$h323_setup_time', '$h323_connect_time','$h323_disconnect_time', '$h323_disconnect_cause', '$h323_voice_quality', '$h323_conf_id')");
	} else { print "ERROR: Unsupported h323calltype \"$h323_call_type\"\n" }
	$sth2->execute();

 	if ($verbose > 0) { print "sent to DB\n"; }
	$sth2->finish();
}

sub db_insert {
	if ($h323_call_type eq 'VoIP') {
        $sth2 = $dbh->prepare("INSERT into StopVoIP (
		AcctTime, UserName, NASIPAddress, AcctSessionTime, AcctInputOctets, AcctOutputOctets,
		CalledStationId, CallingStationId, AcctDelayTime, H323RemoteAddress, h323gwid, h323callorigin,
		callid, h323connecttime, h323disconnectcause, h323disconnecttime, h323setuptime, h323voicequality)
		values(($Timestamp)::abstime, '$UserName', '$NasIPAddress', '$AcctSessionTime', '$AcctInputOctets',
		'$AcctOutputOctets', '$Called_Station_Id', '$Calling_Station_Id', '$AcctDelayTime',
		NULLIF('$h323_remote_address', '')::INET, '$h323_gw_id','$h323_call_origin', '$h323_conf_id',
		NULLIF('$h323_connect_time', '')::TIMESTAMPTZ, '$h323_disconnect_cause',
		NULLIF('$h323_disconnect_time', '')::TIMESTAMPTZ, NULLIF('$h323_setup_time', '')::TIMESTAMPTZ,
		NULLIF('$h323_voice_quality','')::INT4)");

	}
	elsif ($h323_call_type eq 'Telephony') {
        $sth2 = $dbh->prepare("INSERT into StopTelephony (
		AcctTime, UserName, NASIPAddress, AcctSessionTime,
                AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId, AcctDelayTime,
                CiscoNASPort, h323callorigin, callid, h323connecttime, h323disconnectcause, h323disconnecttime, h323setuptime, h323voicequality)
                values(($Timestamp)::abstime, '$UserName', '$NasIPAddress', '$AcctSessionTime', '$AcctInputOctets', '$AcctOutputOctets',
                '$Called_Station_Id', '$Calling_Station_Id', '$AcctDelayTime', '$Cisco_NAS_Port', '$h323_call_origin', '$h323_conf_id',
		'$h323_connect_time', '$h323_disconnect_cause', '$h323_disconnect_time', '$h323_setup_time', '$h323_voice_quality')");
	} else {
		if ($h323_call_type) { print "ERROR: Unsupported h323calltype: \"$h323_call_type\"\n"; }
		else { print "ERROR: Missing \"h323calltype\". This doesn't appear to be a VoIP record."; }
		return;		# Not a VoIP record. Bailout
	 }
	$sth2->execute();
	#my $returned_rows = $sth2->rows;
 	if ($verbose > 0) { print "added to DB\n"; }
	$sth2->finish();
}

## This sub can be used to update data in an existing database if you have some fields not in the Database.
sub db_update {
	my $sth2= $dbh->prepare("UPDATE radacct SET CalledStationId = '$Called_Station_Id',
		AcctTerminateCause = '$AcctTerminateCause', H323RemoteAddress = '$h323_remote_address',
		AcctStatusType = '$AcctStatusType', callid = '$h323_conf_id', h323calltype = '$h323_call_type',
		CiscoNASPort = '$Cisco_NAS_Port', h323disconnectcause = '$h323_disconnect_cause',
		h323connecttime = '$h323_connect_time', h323disconnecttime = '$h323_disconnect_time',
		h323setuptime = '$h323_setup_time' WHERE AcctSessionId = 'AcctSessionId' AND UserName = '$UserName'
		AND NASIPAddress = '$NasIPAddress' AND h323confid = '$h323_conf_id'");
        $sth2->execute();
        my $returned_rows = $sth2->rows;
	if ($verbose > 0) { print " $returned_rows record(s) updated\n" }
        $sth2->finish();

}

sub db_read {
	if ($verbose > 0) { print "Record: $passno) ConfID: $h323_conf_id Timestamp: $radius_record_timestamp Length: $AcctSessionTime "; }
	my $sth = $dbh->prepare("SELECT RadAcctId FROM Stop$h323_call_type
		WHERE AcctTime = ($Timestamp)::abstime
		AND NASIPAddress = '$NasIPAddress'
		AND callid = '$h323_conf_id'")
                or die "\nCouldn't prepare statement: " . $dbh->errstr . "\n";

	my @data;
	$sth->execute()             # Execute the query
		or die "\nCouldn't execute statement: " . $sth->errstr . "\n";
	my $returned_rows = $sth->rows;

          if ($sth->rows == 0) {
		&db_insert;	# It's a new record. All systems go.
          } elsif ($sth->rows == 1) {
                if ($verbose > 0) { print "already in DB.\n"; }
		# FIXME: Make updates an option!
                #while (@data = $sth->fetchrow_array()) {
                #my $dbAcctSessionId = $data[1];
		##&db_update;
                #}
          } else {
		$duplicates++;	 # FIXME: Log this somewhere!
                print "********* More than One Match! We have a problem!\n";
          }

	$sth->finish;
}

sub process_record {
	$radius_record_timestamp = @record[0];
	chomp $radius_record_timestamp;
	if ($verbose > 1) { print "DEBUG: Processing new record with time: $radius_record_timestamp \n"; }
	# Clear the variables we use so that we don't have rubbish from the last loop
	$UserName=""; $NasPort=""; $NasPortType="";
	$NasIPAddress = ""; $AcctStatusType=""; $AcctSessionTime="";
	$AcctInputOctets=""; $AcctOutputOctets=""; $AcctTerminateCause="";
	$ServiceType=""; $FramedProtocol=""; $FramedIPAddress="";
	$Timestamp=""; $AcctDelayTime=0; $ConnectInfo=""; $Called_Station_Id="";
	$SQL_User_Name=""; $Cisco_NAS_Port=""; $Client_IP_Address="";
	$h323_remote_address=""; $h323_disconnect_cause=""; $h323_gw_id="";
	$h323_conf_id=""; $h323_call_type=""; $h323_disconnect_time="";
	$h323_connect_time=""; $h323_setup_time=""; $Calling_Station_Id="";
	$h323_call_origin=""; $h323_voice_quality=""; $h323_gw_id="";

	foreach (@record) {  		# Parse the lines of data into variables.

	# Initial cleanup of junk from the line of data
	s/^\s+//;	# Strip leading spaces.
	s/^Quintum-//;	# Strip leading "Quintum-".
    	chomp;		# Strip trailing CR

	$AcctStatusType = $_ if s/Acct-Status-Type = //;
	if ($AcctStatusType eq "Stop") {		# All the data we need is in Stop records.
	} elsif ($AcctStatusType eq "Start") {
		if ($verbose > 1) { print "DEBUG: Skipping \"Start\" record\n"; }
		return;
	} elsif ($AcctStatusType eq "Alive"){
		if ($verbose > 1) { print "DEBUG: Skipping \"Alive\" record\n"; }
		return;
	};

	$UserName = $_ if s/User-Name = //;
	$NasIPAddress = $_ if s/NAS-IP-Address = //;
	$AcctSessionTime = $_ if s/Acct-Session-Time = //;
	$AcctInputOctets = $_ if s/Acct-Input-Octets = //;
	$AcctOutputOctets = $_ if s/Acct-Output-Octets = //;
	$AcctDelayTime = $_ if s/Acct-Delay-Time = //;
	$Called_Station_Id = $_ if s/Called-Station-Id = //;
	$Calling_Station_Id = $_ if s/Calling-Station-Id = //;
	$Cisco_NAS_Port = $_ if s/Cisco-NAS-Port = //;
	$Timestamp = $_ if s/Timestamp = //;
	if (s/h323-call-type = \"h323-call-type=//) {
                        $h323_call_type = substr($_, 0, -1);
                } elsif (s/h323-call-type = //) {
                        $h323_call_type = $_;
            };
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
	if (s/h323-conf-id = \"h323-conf-id=//) {
                        $h323_conf_id = substr($_, 0, -1);
                } elsif (s/h323-conf-id = //) {
                        $h323_conf_id = $_;
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
        if (s/h323-call-origin = \"h323-call-origin=//) {
                        $h323_call_origin = substr($_, 0, -1);
                } elsif (s/h323-call-origin = //) {
                        $h323_call_origin = $_;
            };
        if (s/h323-gw-id = \"h323-gw-id=//) {
                        $h323_gw_id = substr($_, 0, -1);
                } elsif (s/h323-gw-id = //) {
                        $h323_gw_id = $_;
            };
        if (s/h323-voice-quality = \"h323-voice-quality=//) {
                        $h323_voice_quality = substr($_, 0, -1);
                } elsif (s/h323-voice-quality = //) {
                        $h323_voice_quality = $_;
            };
                # FIXME: ugh, definitely look into using backreference.
                # something like s/(\S+)\s*=\s*\1/\1 = / or so
	  }


	# Remove quotation marks from a bunch of different fields (Stupid Cisco)
	$UserName =~ s/\"//g;
	$h323_remote_address =~ s/\"//g;
	$Called_Station_Id =~ s/\"//g;
	$h323_disconnect_cause =~ s/\"//g;
	$h323_setup_time =~ s/\"//g;
	$h323_connect_time =~ s/\"//g;
	$h323_disconnect_time =~ s/\"//g;
	$h323_conf_id =~ s/\"//g;
	$h323_call_type =~ s/\"//g;
	$h323_call_origin =~ s/\"//g;
	$h323_voice_quality =~ s/\"//g;
	$Cisco_NAS_Port =~ s/\"//g;

	# Remove Remove . from the start of time fields (routers that have lost ntp timesync temporarily)
	$h323_setup_time =~ s/^\.*//;
	$h323_connect_time =~ s/^\.*//;
	$h323_disconnect_time =~ s/^\.*//;

	# Ignore broken fields from some stupid, non-cisco gateways (They shall remain nameless)
	if ($h323_connect_time eq "0") { $h323_connect_time = "" };
	if ($h323_disconnect_time eq "0") { $h323_disconnect_time = "" };

	# If its a valid record continue onto the database functions
	# FIXME: More checks needed here.
	if ($h323_call_type) {
		$passno++;
		#@duplicate_records{$passno} += @record;
		if (&procedure_get()) { &procedure_insert; }
		else { &db_read; }
	} else { if ($verbose > 1) { print "DEBUG: Skipping non-h323 record\n"; } }
}

sub read_record {
	my $keepreading = 1;
	@record = ();
	while ($keepreading) {
		$_ = <DETAIL>;
		print "$_" if ($verbose > 1);
		if ( /^$/ ) {
			$keepreading = 0;	# End of record
		} else {
			$record[++$#record] = $_;
		}
	}
	&process_record;
}

sub read_detailfile {
	my $file_starttime = time(); my $filename = shift; my @record = (); my $record_no = 0;
	if ($verbose > 1) { print "DEBUG: Reading detail file: $filename\n" }
	if ((-r $filename) != 1) { 		# test if the file exists and is readable
		if ($verbose >= 0) { print "INFO: Skipping file \"$filename\" as it is not readable or does not exist.\n" }
		return;
	 }
	if ( $filename =~ /.gz$/ ) {		# Deal with compressed files
		open (DETAIL, "$GZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} elsif ( $filename =~ /.Z$/ ) {
		open (DETAIL, "$ZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} elsif ( $filename =~ /.bz2$/ ) {
		open (DETAIL, "$BZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
	} else {
		open (DETAIL, "<$filename") || warn "read_detailfile(\"$filename\"): $!\n";
	}
	$valid_input = (eof(DETAIL) ? 0 : 1);
	if ($verbose > 1) { print "DEBUG: Starting to read records from $filename\n"; }
	while($valid_input) {
		$valid_input = 0 if (eof(DETAIL));
		if ($verbose > 1) { print "DEBUG: Reading Record\n"; }
		&read_record;
		$record_no++;
	}
	my $file_runtime = (time() - $file_starttime);
	if ($file_runtime < 1) { $file_runtime = 1; }
	my $file_speed = ($record_no / $file_runtime);
        if ($verbose >= 0) { print "\n $record_no total records read from $filename were processed in $file_runtime seconds ($file_speed records/sec) \n"; }
}

sub print_usage_info {
	print "\n";
	$leader = "$progname $version Usage Information";
	$underbar = $leader;
	$underbar =~ s/./-/g;
	print "$leader\n$underbar\n";
	print "\n";
	print "  Syntax:   h323detail2db.pl [ options ] detailfile(s)\n";
	print "\n";
	print "    -d --database                    Database to use\n";
	print "    -h --help                        Show this usage information\n";
	print "    -H --host                        Database host to connect to (Default: localhost)\n";
	print "    -p --procedure                   Use Postgresql stored procedure (BROKEN!)\n";
	print "    -q --quiet                       Turn on quiet mode (No Output)\n";
	print "    -v --verbose                     Turn on verbose\n";
	print "    -V --version                     Show version and copyright\n";
	print "    -x --debug                       Turn on debugging\n";
	print "\n";
}

sub procedure_get() {
        return $stored_procedure;
}

sub procedure_set($) {
        $stored_procedure = $_[0];
}


sub main {
        # Parse the command line for options
        if (!scalar(@ARGV)) {
        	&print_usage_info();
		exit(SUCCESS);
	};

	# See the Getopt::Long man page for details on the syntax of this line
	@valid_opts = ("h|help", "V|version", "f|file=s", "x|debug", "d|database=s", "v|verbose+" => \$verbose, "q|quiet+" => \$quiet, "D|date=s", "H|host=s", "p|procedure");
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
		print "$progname Version $version by Peter Nixon - http://www.peternixon.net/\n";
		print "Copyright (c) 2002-2004 Peter Nixon\n";
		print "  ($rcs_info)\n";
		print "\n";
		return SUCCESS;
	} elsif ($opt_h) {
	        &print_usage_info();
	        exit(SUCCESS);
	}

	if ($opt_x) {
		print "DEBUG: Debug mode is enabled.\n";
		$verbose = 2;
	} elsif ($quiet) { $verbose -= $quiet; }
	&procedure_set($opt_p);
	if ($opt_d) {
		if ($verbose > 0) { print "Using database \"$opt_d\" instead of default database \"$database\"\n"; }
		$database = $opt_d;
	}

	if (@ARGV) {
		my $db_host;
		if ($opt_H) { $db_host = $opt_H; }
		else { $db_host = "localhost"; }
		&db_connect($db_host);

        	# Loop through the defined files
	        foreach $file (@ARGV) {
			&read_detailfile($file);
	        }
		&process_duplicates;
		&db_disconnect($db_host);

		my $runtime = (time() - $starttime);
		if ($runtime < 1) { $runtime = 1; }
		my $speed = ($passno / $runtime);
	        if ($verbose >= 0) { print "\n $passno valid records were processed in $runtime seconds ($speed records/sec) \n"; }
	} else {
		print "ERROR: Please specify one or more detail file(s) to import.\n";
		exit(FAILURE);
	}

}


exit &main();
