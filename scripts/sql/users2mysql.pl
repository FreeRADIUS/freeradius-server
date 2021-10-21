#!/usr/bin/perl -w
#
# users2mysql.pl -- a script to parse a RADIUS users file and fill
#                   a freeradius mysql database...
#
#
# Script developed by Rich Puhek, Znet Telecom
#
# last change: Aug 8th, 2002.
#

use strict;

#Modify to suit your db.
my $db="radius";
my $hostname="localhost";
my $user="radius";
my $password="passwd";


#location of source users file:
my $users_file="/etc/raddb_cistron_backup/users";


#The following are defaults from freeradius 0.7
#  ...shouldn't have to change.
my $groups_table="usergroup";
my $check_table="radcheck";
my $reply_table="radreply";

my $debug=3;

use DBD::mysql;

#open the users file, and the db.
open(my $USERS, '<', $users_file) or die "ERROR: Unable to open $users_file $!\n";
my $database = DBI->connect("DBI:mysql:$db:$hostname",$user, $password) or die "ERROR: Unable to connect to $db on $hostname $!\n";

sub check_attribs {

	if (!defined($_[0]) or !defined($_[1])) {
		print "undefined parameter!\n";
		return;
	};

	my $attr = $_[0];
	my $val  = $_[1];

	if ($attr !~ /Password|Framed-IP-Address|Framed-IP-Netmask|Framed-IP-Routing|Framed-Routing|Framed-IP-Route|Password|Simultaneous-Use|Idle-Timeout|Auth-Type|Service-Type|Netmask|Framed-Protocol/ ) {
		print "unrecognized attribute: $attr\n" if $debug>1;
		return;
	};

	return if ( (! defined($val) ) or
		( ($attr =~ /Simultaneous\-Use/i) && ( $val !~ /^[0-9]*$/ ) )
		);
	print "attribs ok!\n" if $debug>3;
	return "TRUE";
};

sub cleanup {
	#clean up variables: strip leading/trailing spaces and trailing commas...
	my $myval;
	$myval = $_[0];
	$myval =~ s/^\s//g;
	$myval =~ s/\s$//g;
	$myval =~ s/,$//;
	return $myval;
};


sub user_attribute {
	#push values into db...
	my $dtable=$_[0];
	my $duser=$_[1];
	my $dattrib=$_[2];
	my $dval=$_[3];

	print "inserting \"$dattrib\", \"$dval\" for \"$duser\" in rad$dtable\n" if ( $dtable !~ /group/ and $debug>2);
	print "inserting \"$duser\" into usergroup table as member of \"$dattrib\"\n" if ( $dtable =~ /group/ and $debug>2);

	my $table;
	if ( $dtable =~ /group/ ) {
		$table = "usergroup";
	} elsif ( $dtable =~ /check/ ) {
		$table = "radcheck";
	} elsif ( $dtable =~ /reply/ ) {
		$table = "radreply";
	} else {
		die "argh! what table is $dtable?\n";
	};

	my $return;
	if ( $table =~ /usergroup/ ) {
		if ( $dattrib =~ /static/ ) {
			#Delete the "dynamic" entry...
			$return = $database->do ("DELETE FROM `$table` WHERE `UserName`='$duser' LIMIT 1");
		};
		$return = $database->do ("INSERT INTO `$table` SET `UserName`='$duser',`GroupName`='$dattrib'");

	} else {
		$return = $database->do ("INSERT INTO `$table` SET `UserName`='$duser',`Attribute`='$dattrib',`Value`='$dval', `op`=':='");
	};
	return $return;
};


while (<$USERS>) {

	chop;
	#Skip comment lines and blank lines...
	next if ( /^\#/ );
	next if ( /^$/ );
	next if ( /^\s*$/ );

	my @attribs;
	if ( /^[a-zA-Z0-9]+/ ) {
		print "located a user entry: $_\n" if $debug>6;
		my ($user,$rest) = split /\s/, $_, 2;
		#Put user into usergroup as dynamic, if the user's attributes
		# include an IP address, the script will change that later...
		user_attribute("group",$user,"dynamic","");
		@attribs = split /,/, $rest;
	} else {
		# Already found the user, now finding attributes...
		@attribs = $_;
	};

	foreach my $attr (@attribs) {
		my ($attrib,$value) = split /=/, $attr, 2;
		#TODO: insert sanity checks here!
		$value  = cleanup($value)  if (defined($value));
		$attrib = cleanup($attrib) if (defined($attrib));
		unless (check_attribs($attrib,$value)) {
			print "ERROR: something bad with line $.: \"$attrib\", \"$value\"\n";
			next;
		};
		print "attrib: $attrib has value: $value\n" if $debug>8;

		if ( $attrib =~ /Framed-IP-Address/ ) {
			#user is a static IP user...
			user_attribute("group",$user,"static","");
		};

		if ( $attrib =~ /Password|Simultaneous-Use/ ) {
			#This is an individual check attribute, so we'll pass it along...
			user_attribute("check",$user,$attrib,$value);
		};
		if ( $attrib =~ /Framed-IP-Address|Framed-IP-Routing|Framed-Routing/ ) {
			#This is an individual reply attribute, so we'll pass this along...
			user_attribute("reply",$user,$attrib,$value);
		};
	};

};

close $USERS;
exit($database->disconnect);
