#!/usr/bin/perl
#
# syslog2db - Extract Clarent VoIP CDRs from billing_record files and 
# insert them into a Postgresql database. 
#
# Author:       Peter Nixon <codemonkey@peternixon.net>
# Date:         2003-05-07
# Summary:      Clarent, VoIP, CDR, database, postgresql
# Copyright:    2002, Peter Nixon <codemonkey@peternixon.net>
# Copy Policy:  Free to copy and distribute provided all headers are left
#               intact and no charge is made for this program.  I would
#               appreciate copies of any modifications to the script.
# URL:          http://www.peternixon.net/code/
#
# $Id$


# Modules we use to make things easier
use POSIX;
require DBI;
require Getopt::Long;
use Carp;
use Symbol;
use Time::Local;
#use strict;	# Errrm. That looks like effort :-)


# Program and File locations
# gzcat - 'cat for .gz / gzip files'
# If you don't have gzcat and do have gzip then use: ln gzip gzcat
my $GZCAT = "/usr/bin/zcat";
# zcat - 'cat for .Z / compressed files'
my $ZCAT = "/usr/bin/zcat";
# bzcat - 'cat for .bz2 files'
my $BZCAT = "/usr/bin/bzcat";

#### You should not have to modify anything below here

$| = 1; 	#Unbuffered output
my $progname = "clarent2db.pl";
my $progname_long = "Clarent Billing Record to DB Importer";
my $version = 0.2;

# Set up some basic variables
my $double_match_no = 0; my $verbose = 0; my $recordno = 0; my $fileno = 0; my $lineno = 0;
my $starttime = time();


# Database Information
my $database    = "clarent";
my $defaulthostname    = "ist-db1";
my $port        = "3306";
my $user        = "postgres";
my $password    = "";

# Defaults
my $defaulttimezone = "UTC";
my $defaultyear = 2002;
my $dbh; 

# fast timelocal
my $str2time_last_time;
my $str2time_last_day;
my $str2time_last_month;
my $enable_year_decrement = 1; # year-increment algorithm: if in january, if december is seen, decrement
                               # year
my %working_record = ();

my %months_map = (
    'Jan' => 0, 'Feb' => 1, 'Mar' => 2,
    'Apr' => 3, 'May' => 4, 'Jun' => 5,
    'Jul' => 6, 'Aug' => 7, 'Sep' => 8,
    'Oct' => 9, 'Nov' =>10, 'Dec' =>11,
    'jan' => 0, 'feb' => 1, 'mar' => 2,
    'apr' => 3, 'may' => 4, 'jun' => 5,
    'jul' => 6, 'aug' => 7, 'sep' => 8,
    'oct' => 9, 'nov' =>10, 'dec' =>11,
);

sub db_connect {
        my $hostname = shift;
        if ($verbose > 1) { print "DEBUG: Connecting to Database Server: $hostname\n" }
        if ($hostname eq 'localhost') {
        if ($verbose > 1) { print "DEBUG: localhost connection so using UNIX socket instead of network socket.\n" }
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
        if ($verbose > 1) { print "DEBUG: Disconnecting from Database Server\n" }
        $dbh->disconnect
            or warn "Disconnection failed: $DBI::errstr\n";
}

sub db_read {
        $passno++;
        if ($verbose > 0) { print "Record: $passno) Conf ID: $working_record{h323confid}   Start Time: $working_record{start_time} IP: $working_record{ip_addr_egress} Call Length: $working_record{duration}\n"; }
        my $sth = $dbh->prepare("SELECT Id FROM billing_record
                WHERE start_time= ?
                AND ip_addr_ingress = ?
                AND h323confid = ?")
                or die "Couldn't prepare statement: " . $dbh->errstr;

          my @data;
          $sth->execute($working_record{start_time}, $working_record{ip_addr_egress}, $working_record{h323confid})             # Execute the query
            or die "Couldn't execute statement: " . $sth->errstr;
           my $returned_rows = $sth->rows;

          if ($sth->rows == 0) {
                &db_insert;
          } elsif ($sth->rows == 1) {
                if ($verbose > 0) { print "Exists in DB.\n"; }
          } else {
                $double_match_no++;
                # FIXME: Log this somewhere!
                print "********* More than One Match! We have a problem!\n";
          }

        $sth->finish;

}

sub db_insert {
        $sth2 = $dbh->prepare("INSERT into billing_record (local_SetupTime, start_time, duration, service_code, phone_number,
		ip_addr_ingress, ip_addr_egress, bill_type, disconnect_reason, extended_reason_code, dialed_number, codec, h323ConfID)
                values(?,?,?,?,?,?,?,?,?,?,?,?,?)");

         $sth2->execute($working_record{local_setuptime}, $working_record{start_time}, $working_record{duration},
		$working_record{service_code}, $working_record{phone_number}, $working_record{ip_addr_egress}, $working_record{ip_addr_egress},
		$working_record{bill_type}, $working_record{disconnect_reason}, $working_record{extended_reason_code}, $working_record{dialed_number},
		$working_record{codec}, $working_record{h323confid});             # Execute the query
        #my $returned_rows = $sth2->rows;
        if ($verbose > 0) { print "$sth2->rows rows added to DB\n"; }
        $sth2->finish();

}

sub file_read {
        my $filename = shift;
        if ($verbose > 1) { print "DEBUG: Reading detail file: $filename\n" }
        if ( $filename =~ /.gz$/ ) {
                open (FILE, "$GZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
        } elsif ( $filename =~ /.Z$/ ) {
                open (FILE, "$ZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
        } elsif ( $filename =~ /.bz2$/ ) {
                open (FILE, "$BZCAT $filename |") || warn "read_detailfile(\"$filename\"): $!\n";
        } else {
                open (FILE, "<$filename") || warn "read_detailfile(\"$filename\"): $!\n";
        }
        $valid_input = (eof(FILE) ? 0 : 1);
        if ($verbose > 1) { print "DEBUG: Starting to read records from $filename\n"; }
        while($valid_input) {
                $valid_input = 0 if (eof(FILE));
                if ($verbose > 1) { print "DEBUG: Reading Record\n"; }
                $_ = <FILE>;
		$lineno++;
                if ($verbose > 1) { print "DEBUG RECORD: $_"; }
		#&record_mangle($_);
		&record_match($_);
        }
}

# 0: sec, 1: min, 2: h, 3: day, 4: month, 5: year
sub str2timez($$$$$$$) {
    my $GMT = pop @_;
    my $day_secs = $_[2]*3600+$_[1]*60+$_[0];
    if(defined $str2time_last_time) {
        if( $_[3] == $str2time_last_day and
            $_[4] == $str2time_last_month )
        {
            return $str2time_last_time + $day_secs;
        }
    }

    my $time;
    if($GMT) {
        $time = timegm(@_);
    }
    else {
        $time = timelocal(@_);
    }

    $str2time_last_time = $time - $day_secs;
    $str2time_last_day = $_[3];
    $str2time_last_month = $_[4];

    return $time;
}

sub getseconds($$) {
	my $time1 = pop @_;
	my $time2 = pop @_;
	
	my $seconds = $time = str2time($time1) - str2time($time2);
	if ($verbose > 0) { print "******** Seconds: $seconds\n"; }
	return $seconds;
}

sub record_match($) {
	chomp($_);
        #if ($verbose > 1) { print "DEBUG Record: $_\n"; }
        # Check to see if it is a Clarent Billing record
        if ( /^
            (\S{3})\/(\d+)\/(\d{4})  	# Month Day Year
            \s
            (\d+):(\d+):(\d+) 		# Hour Min Sec
            \s
	    (\d{4}) 			# msec??
	    \s
	    \w*?:?			# RESEND: (Discarded)
            \s?
	    \S{1}, 			# U (Discarded)
	    (\w+),			# EGRESS
	    (\w+),			# ISTOUT
	    (\d+),			# start_time
	    (\d+),			# duration
	    (\w),			# service_code
	    (\w+-\w+-\w+),		# phone_number
	    (\d+\.\d+\.\d+\.\d+),	# ip_addr_ingress
	    (\d+\.\d+\.\d+\.\d+),	# ip_addr_egress
	    (\d+),			# h323confid
	    \w*,			# 
	    (\w+),			# 
	    (\w+),			# 
	    (\d+),			# 
	    (\w+),			# 
	    (\w{2}),			# disconnect_reason
	    (\w{2}),			# extended_reason_code
            (.*),				# text we don't care about
	    (\d+),			# dialed_number??
	    \w*,			# 
	    \w*,			# 
	    (\w+),			# codec
	    \w*,			# 
	    \w*				# 
            /x ) {
		$recordno++; %working_record = ();
		if ($verbose > 0) { print "DEBUG: Cleaned Record: $3-$1-$2 $4:$5:$6 $7 $8 : $9 $10 $11 $12 $13 $14 $15 $16 $17 $18 $19 $20 $21 $22 $23 $24 :: $25 $26 $27 $28 $29\n"; }
		# parse out values
	        my $month = $months_map{$1}; defined $month or croak "ERROR: Unknown month \"$1\"\n";
		my $days = $2;
		my $years = $3;
		my $hours = $4;
               	my $minutes = $5;
               	my $seconds = $6;
		$working_record{local_setuptime} = "$years-$month-$days $hours:$minutes:$seconds";
		$working_record{start_time} = $10;
		$working_record{duration} = $11;
		$working_record{service_code} = $12;
		$working_record{phone_number} = $13;
		$working_record{ip_addr_ingress} = $14;
		$working_record{ip_addr_egress} = $15;
		$working_record{h323confid} = $16;

	#	$cust_city_call_totals{$custname}{$nascity} += $mins;
	        # convert to unix time 0: sec, 1: min, 2: h, 3: day, 4: month, 5: year
	        my $unixtime = str2timez($seconds,$minutes,$hours,$days,$month,$years,$defaulttimezone);
		if ($verbose > 0) { print "DEBUG: Time is $unixtime\n"; }
		&db_read;
        } elsif ( /^
            (\S{3})\/(\d+)\/(\d{4})     # Month Day Year
            \s
            (\d+):(\d+):(\d+)           # Hour Min Sec
            \s
            (\d{4})                     # msec??
            \s
            FAILED\sTO\sSEND            # FAILED TO SEND (Discarded)
            /x ) {
				# Broken FAILED TO SEND record with date time and nothing else
        } elsif ( /^
            (\S{3})\/(\d+)\/(\d{4})     # Month Day Year
            \s
            (\d+):(\d+):(\d+)           # Hour Min Sec
            \s
            (\d{4})                     # msec??
            \s
            FAILED\sTO\sWRITE
                \srcd\s\=\s\d+          # FAILED TO WRITE (Discarded)
            /x ) {
				# Broken FAILED TO WRITE record with date time and nothing else
        } elsif ( /^
            (\S{3})\/(\d+)\/(\d{4})     # Month Day Year
            \s
            (\d+):(\d+):(\d+)           # Hour Min Sec
            \s
            (\d{4})                     # msec??
            /x ) {
				# Broken record with date time and nothing else
	} else {
            if ($verbose > 0) { print "ERROR: Record is not in Clarent format: $str\n"; }
        };
}

sub print_usage_info {
        print "\n";
        my $leader = "$progname_long Ver: $version Usage Information";
        my $underbar = $leader;
        $underbar =~ s/./-/g;
        print "$leader\n$underbar\n";
        print "\n";
        print "  Syntax:   $progname [ options ] file\n";
        print "\n";
        print "    -h --help                        Show this usage information\n";
        print "    -v --verbose                     Turn on verbose\n";
        print "    -x --debug                       Turn on debugging\n";
        #print "    -p --procedure                   Use Postgresql stored procedure (faster!)\n";
        print "    -V --version                     Show version and copyright\n";
        print "    -H --host                        Database host to connect to (Default: localhost)\n";
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
	my $quiet = 0;

        # See the Getopt::Long man page for details on the syntax of this line
        @valid_opts = ("h|help", "V|version", "f|file=s", "x|debug", "v|verbose+" => \$verbose, "q|quiet+" => \$quiet, "D|date=s", "H|host=s", "p|procedure");
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
                print "Copyright (c) 2003 Peter Nixon\n";
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

        if (@ARGV) {
                if ($opt_H) { &db_connect($opt_H);
                } else { &db_connect($defaulthostname); }

                # Loop through the defined files
                foreach my $file (@ARGV) {
			$fileno++;
                        &file_read($file);
                }
        my $runtime = (time() - $starttime);
        if ($runtime > 0) {
        } else { $runtime = 1; }
        my $speed = ($recordno / $runtime);
        if ($verbose >= 0) { 
		if ($fileno > 1) { 
			print "\n $recordno records from $lineno lines in $fileno files were processed in ~$runtime seconds (~$speed records/sec) \n"; 
		} else {
			print "\n $recordno records from $lineno lines in $filename were processed in ~$runtime seconds (~$speed records/sec) \n"; 
		}
	}

                &db_disconnect;
        } else {
                print "ERROR: Please specify one or more detail file(s) to import.\n";
                exit(FAILURE);
        }
}

exit &main();
