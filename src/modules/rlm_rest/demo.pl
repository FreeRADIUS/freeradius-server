#!/usr/bin/perl

use strict;
use warnings;

use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;

# Required else we get weird issues ports being bound after the
# daemon exits.
my $daemon;
my $client;

sub close_client {
	if (defined $client) {
		$client->shutdown(2);
		$client->close();
	}
}

sub close_daemon {
	if (defined $daemon) {
		print "Closing daemon socket\n";
		$daemon->shutdown(2);
		$daemon->close();
	}
	close_client();
}

$SIG{'INT'} = \&close_daemon;
$SIG{'QUIT'} = \&close_daemon;
$SIG{'PIPE'} = \&close_client;

$daemon = new HTTP::Daemon(ReuseAddr => 1, LocalAddr => '127.0.0.1', LocalPort => 9090);
if (!defined $daemon) {
	die "Error opening socket: $!";
}

printf("Please contact me at: %s\n", $daemon->url);
while ($client = $daemon->accept) {
	$client->timeout(1);
	while (my $r = $client->get_request) {
		printf("Got %s request for %s\n", $r->method, $r->url->path);
		if (($r->method eq 'POST') or ($r->method eq 'GET')) {
			my $resp = HTTP::Response->new('200', 'OK');

			$resp->header('Content-Type' => 'application/json');
			$resp->content('{"control.Password.Cleartext":"testing123","reply.Reply-Message":"Hello from demo.pl"}');

			$client->send_response($resp);
		} else {
			$client->send_error(RC_FORBIDDEN)
		}
	}

	close_client();
	undef($client);
}
