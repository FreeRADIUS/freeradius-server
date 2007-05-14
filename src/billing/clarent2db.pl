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
#use Symbol;
#use Time::Local;
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
my $defaulthostname    = "localhost";
my $port        = "3306";
my $user        = "postgres";
my $password    = "";

# Defaults
my $defaulttimezone = "UTC";
my $defaultyear = 2003;
my $dbh;

my %working_record = ();

my %months_map = (
    'Jan' => '01', 'Feb' => '02', 'Mar' => '03',
    'Apr' => '04', 'May' => '05', 'Jun' => '06',
    'Jul' => '07', 'Aug' => '08', 'Sep' => '09',
    'Oct' => '10', 'Nov' => '11', 'Dec' => '12',
    'jan' => '01', 'feb' => '02', 'mar' => '03',
    'apr' => '04', 'may' => '05', 'jun' => '06',
    'jul' => '07', 'aug' => '08', 'sep' => '09',
    'oct' => '10', 'nov' => '11', 'dec' => '12',
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
        my $sth = $dbh->prepare("SELECT ID FROM billing_record
                WHERE start_time = ?
                AND ip_addr_ingress = ?
                AND h323confid = ?")
                or die "Couldn't prepare statement: " . $dbh->errstr;

          my @data;
          $sth->execute($working_record{start_time}, $working_record{ip_addr_ingress}, $working_record{h323confid})             # Execute the query
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
		ip_addr_ingress, ip_addr_egress, bill_type, disconnect_reason, extended_reason_code, dialed_number, codec, h323ConfID, port_number)
                values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

         $sth2->execute($working_record{local_setuptime}, $working_record{start_time}, $working_record{duration},
		$working_record{service_code}, $working_record{phone_number}, $working_record{ip_addr_ingress}, $working_record{ip_addr_egress},
		$working_record{bill_type}, $working_record{disconnect_reason}, $working_record{extended_reason_code}, $working_record{dialed_number},
		$working_record{codec}, $working_record{h323confid}, $working_record{port_number});
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
                if ($verbose > 2) { print "DEBUG: Reading Record\n"; }
                $_ = <FILE>;
		$lineno++;
                if ($verbose > 1) { print "DEBUG Raw Record: $_"; }
		#&record_mangle($_);
		&record_match($_);
        }
}

sub record_match($) {
	chomp($_);

        # Spilt the Call record up into fields
        my @callrecord = split(/,/, $_);

	if (scalar(@callrecord) == 70) { 	# Check that we have the right number of fields for a Clarent record
        	if ($verbose > 1) { print "DEBUG: Clean Record: @callrecord\n"; }
		$recordno++; %working_record = ();
		$working_record{local_setuptime} = clarent2normaltime($callrecord[0]);
                $working_record{start_time} = $callrecord[3];	# This is in Unix timetamp format, relative to the originating gateway.
								# It is therefore useless unless ALL gateways are set with the same timezone,
								# so I don't bother to convert it to datetime format.
                $working_record{duration} = $callrecord[4];
                $working_record{service_code} = $callrecord[5];
                $working_record{phone_number} = $callrecord[6];
                $working_record{ip_addr_ingress} = $callrecord[7];
                $working_record{ip_addr_egress} = $callrecord[8];
                $working_record{h323confid} = $callrecord[9];
                $working_record{bill_type} = $callrecord[12];
                $working_record{disconnect_reason} = $callrecord[15];
                $working_record{extended_reason_code} = $callrecord[16];
                $working_record{port_number} = $callrecord[21];
                $working_record{dialed_number} = $callrecord[60];
                $working_record{codec} = $callrecord[67];

		&db_read;

	} else { if ($verbose > 1) { print "DEBUG: ERROR: Record is not in Clarent format: $str\n"; } }


}

sub clarent2normaltime($) {
        if ( /^
            (\S{3})\/(\d+)\/(\d{4})     # Month Day Year
            \s
            (\d+):(\d+):(\d+)           # Hour Min Sec
            \s
            (\d{4})                     # msec??
            \s
            \w*?:?                      # RESEND: (Discarded)
            \s?
            \S{1}                       # U (Discarded) FIXME: does anyone know what this value means??
            /x ) {
                my $month = $months_map{$1}; defined $month or croak "ERROR: Unknown month \"$1\"\n";
                my $days = $2;
                my $years = $3;
                my $hours = $4;
                my $minutes = $5;
                my $seconds = $6;
                return "$years-$month-$days $hours:$minutes:$seconds";
        } else {
            if ($verbose > 0) { print "ERROR: Not in Clarent time format: $str\n"; }
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
        print "    -V --version                     Show version and copyright\n";
        print "    -H --host                        Database host to connect to (Default: localhost)\n";
        print "\n";
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

        if (@ARGV) {
                if ($opt_H) { &db_connect($opt_H);
                } else { &db_connect($defaulthostname); }

		if (scalar(@ARGV) > 1) {
        	       	foreach $file (@ARGV) { 		# Loop through the defined files
				$fileno++;
                        	&file_read($file);
                	}
		} else {
			$file = @ARGV[0];
                       	&file_read($file);
		}
	        if ($verbose >= 0) {
		        my $runtime = (time() - $starttime);
		        if ($runtime < 1) { $runtime = 0.5; }		# Prevent divide-by-zero errors
		        my $speed = ($recordno / $runtime);
			if ($fileno > 1) {
				print "\n$recordno records from $lineno lines in $fileno files were processed in ~$runtime seconds (~$speed records/sec)\n";
			} else {
				print "\n$recordno records from $lineno lines in $file were processed in ~$runtime seconds (~$speed records/sec)\n";
			}
		}

                &db_disconnect;
        } else {
                print "ERROR: Please specify one or more detail files to import.\n";
                exit(FAILURE);
        }
}

exit &main();
