#!/usr/bin/perl

# Purpose:  create lots of random users and passes
# for testing your radius server
# Read doc/README.testing for more information

use strict;
use warnings;

my $passfile = "./passwd";
my $shadfile = "./shadow";
my $radfile = "./radius.test";
my $nocrypt = "./passwd.nocrypt";
my $users = "./radius.users";

my $numusers;
my %userlist;

if($ARGV[0] eq "") {
	print "\n\tUsage:  $0  <number of users>\n\n";
	exit(1);
} else {
	$numusers = $ARGV[0];
}
my $userlen = 6;
my $passlen = 6;

open(my $PASS, ">", $passfile) || die "Can't open $passfile";
open(my $SHAD, ">", $shadfile) || die "Can't open $shadfile";
open(my $RAD, ">", $radfile) || die "Can't open $radfile";
open(my $NOCRYPT, ">", $nocrypt) || die "Can't open $nocrypt";
open(my $USERS, ">", $users) || die "Can't open $users";

for (my $num=0; $num<$numusers; $num++) {
	# generate username
	my $username = "";
	for(my $i=0; $i<rand($userlen)+2; $i++) {
		my $char;
		do { ($char = chr((rand 25)+97))} until $char=~/[A-Za-z]/;
		$username .= $char;
	}
	# Make sure they're unique
	if(($userlist{$username}) || (getpwnam($username))) {
		$num--;
		next;
	}
	$userlist{$username} = 1;

	# generate password
	my $password = "";
	for(my $i=0; $i<rand($passlen)+2; $i++) {
		my $char;
		do { ($char = chr((rand 25)+97))} until $char=~/[A-Za-z]/;
		$password .= $char;
	}

	if (length($num)%2==1) {
		$num="0".$num;
	}
	printf $PASS "$username:%s:1001:1001:Name:/dev/null:/dev/null\n", crypt($password, $password);
	printf $SHAD "$username:%s:1000:0:99999:7:::\n", crypt($password, $password);
	printf $RAD  "User-Name=$username, User-Password=$password,NAS-IP-Address=127.0.0.1,NAS-Port-Id=0\n\n";
	print $NOCRYPT "$username:$password\n";
	print $USERS "$username  Password.Cleartext := \"$password\"\n\tClass=\"0x$num\"\n\n";
}

close($PASS);
close($SHAD);
close($RAD);
close($NOCRYPT);
close($USERS);
print "\nCreated $numusers random users and passwords\n\n";
