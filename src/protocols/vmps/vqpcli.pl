#!/usr/bin/env perl

#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

#
# vqpcli.pl -s localhost -v mydomain -w 10.0.0.1 -i 2/4 -m 0010.a49f.30e3
#

use strict;
use warnings;

use Socket;
$|=0;
my $DEBUG=0;

sub formatItem {

	my $mybuf;
	undef($mybuf);

	my $itemheader = shift;
	my $itemvalue = shift;

	$mybuf = pack("H*",(unpack("a*",$itemheader))); # Add header

	my $payload = pack("a*",(unpack("a*",$itemvalue)));
	my $length = length($payload);
	$length = pack("H*",(unpack("a*",sprintf("%04x",$length))));

	$mybuf = $mybuf . $length . $payload; # Add payload + length

	return $mybuf;
}

sub parseOpts {
	use Getopt::Std;
	my $errors = "";

	our %opt;
	getopts("s:p:v:w:i:m:t:c:x",\%opt) or usage();
	usage() if $opt{h};
	my %request = (
		server_ip	=>	$opt{s} || "",
		client_ip 	=> 	$opt{w} || "127.0.0.1", # IP to say we are - VMPS doesn't care
		port_name 	=> 	$opt{i} || "Fa0/1", # Default port name to use
		vlan 		=>	$opt{c} || "", # Isn't really needed.
		port 		=>	$opt{p} || "1589", # UDP port
		vtp_domain	=>	$opt{v} || "", # Is kinda important
		macaddr		=>	$opt{m} || "", # Likewise...
		debug 		=> 	$opt{x} || "0", # do debugging?
	);

	$errors=$errors . "MAC address must be in nnnn.nnnn.nnnn format\n"
		unless $opt{m} && $opt{m} =~ /[a-z0-9][a-z0-9][a-z0-9][a-z0-9]\.[a-z0-9][a-z0-9][a-z0-9][a-z0-9]\.[a-z0-9][a-z0-9][a-z0-9][a-z0-9]/;
	$opt{m} =~ tr/A-Z/a-z/ if $opt{m};
	$errors=$errors . "VTP Domain must be specified\n" unless defined $opt{v};
	$errors=$errors . "No Server name specified\n" unless defined $opt{s};
	print STDERR $errors if ($errors);
	usage() if ($errors);
	$request{macaddr} =~ s/\.//g;

	return %request;
}

sub usage {
        print STDERR << "EOO";
Options:
-s ip      VMPS Server to query
-p port    UDP port to query
-v domain  VMPS/VTP Domain to query
-w ip      client switch IP to query for
-i iface   client switch Interface name (ie: Fa0/17)
-m macaddr attached device MAC address in nnnn.nnnn.nnnn format
-c vlan    Vlan to reconfirm membership to

EOO
	exit(1);

}

sub makeVQPrequest {

	my %request = %{$_[0]};

	# Header...
	my $buf = pack("H*",(unpack("a*","01"))); # Header bit

	# Is a request to join a vlan
	$buf = $buf . pack("H*",(unpack("a*","01"))); # Is a request

	# No error
	$buf = $buf . pack("H*",(unpack("a*","00"))); # No error

	# 6 data items in inbound payload
	$buf = $buf . pack("H*",(unpack("a*","06")));

	# Sequence number of request
	$buf = $buf . pack("H*",(unpack("a*","000 1234"))); # Bogus sequence number

	# Add Client switch IP
	$buf = $buf . formatItem("000 0c01",(sprintf("%s",unpack("a*",inet_aton($request{client_ip})))));

	# Add Port Name
	$buf = $buf . formatItem("000 0c02",$request{port_name}); # Payload

	# Add VLAN to confirm to buffer
	$buf = $buf . formatItem("000 0c03",$request{vlan}); # Payload

	# Add VTP domain name
	$buf = $buf . formatItem("000 0c04",$request{vtp_domain}); # Payload

	# Add UNKNOWN data to buffer...
	$buf = $buf . pack("H*",(unpack("a*","000 0c07"))); # Header
	$buf = $buf . pack("H*",(unpack("a*","0001 0"))); # Unknown filler

	# Add MAC address to buffer
	$buf = $buf . formatItem("000 0c06",sprintf("%s",pack("H*",(unpack("a*",$request{macaddr}))))); # Payload

	return "$buf";
}

sub sendVQP {

	my $HOSTNAME= shift;
	my $PORTNO=shift;
	my $buf = shift;

	if ($DEBUG==1) {
		print "==============================\n";
		print "MESSAGE SENT:\n";
		open(my $HEX, "|", "/usr/bin/hexdump");
		select $HEX;
		print $buf;
		close $HEX;
		select STDOUT;
		print "==============================\n";
	}

	socket(SOCKET, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";

	my $ipaddr   = inet_aton($HOSTNAME);
	my $portaddr = sockaddr_in($PORTNO, $ipaddr);
	send(SOCKET, $buf, 0, $portaddr) == length($buf)
	        or die "cannot send to $HOSTNAME($PORTNO): $!";

	$portaddr = recv(SOCKET, $buf, 1500, 0); # or die "recv: $!";

	if ($DEBUG==1) {
		print "MESSAGE RECV:\n";
		open(my $HEX, "|", "/usr/bin/hexdump");
		select $HEX;
		print $buf;
		close $HEX;
		select STDOUT;
		print "==============================\n";
	}
	return "$buf";
}

sub parseVQPresp {

	my %response = (
		status		=>	"",
		vlan 		=>	"",
		macaddr		=>	"",
	);

	my $buf = shift;
	$buf =~ /^(.)(.)(.)(.)(....)/;
	my ($header,$type,$status,$size,$sequence) =
		(ord($1),ord($2),ord($3),ord($4),pack("a*",(unpack("H*",$5))));

	$buf =~ s/^........//;

	$response{status}="ALLOW" if ($status == 0);
	$response{status}="DENY" if ($status == 3);
	$response{status}="SHUTDOWN" if ($status == 4);
	$response{status}="WRONG_DOMAIN" if ($status == 5);

	for (my $i=1;$i<=$size;$i++) {

		my $payload_type=pack("a*",(unpack("H*",substr($buf,0,4))));
		my $payload_size=sprintf("%d",hex(pack("a*",(unpack("H*",substr($buf,4,2))))));
		my $payload=substr($buf,6,$payload_size);

		if ($payload_type eq "00000c03") {
			$response{vlan}=$payload;
		} elsif ($payload_type eq"00000c08") {
			$response{macaddr}=pack("a*",(unpack("H*",$payload)));
		}
		substr($buf,0,($payload_size + 6)) = "";
	}
	return %response;
}

my %request=parseOpts();
$DEBUG = $request{debug};

my $buf = makeVQPrequest(\%request);
$buf = sendVQP($request{server_ip},$request{port},$buf);
my %response = parseVQPresp($buf);
print "Vlan: $response{vlan}\nMAC Address: $response{macaddr} \nStatus: $response{status}\n";
