#!/usr/bin/perl -w

# Copyright 2012 Thomas Glanzmann <thomas@glanzmann.de>
# based on POE: Cookbook - UNIX Servers example server writen by James March

use strict;
use warnings FATAL => 'all';

use POE;
use POE::Wheel::SocketFactory;
use POE::Wheel::ReadWrite;

# If e-mail is specified, an e-mail will be send to the user.
# If mobile is specified, an SMS will be send to the user.

my %users = (
        'Administrator' => { email => 'devnull@binary.net', mobile => '49176xxx' },
);

my $otp_lifetime = 600;

my $sipgateurl = 'https://login:password@samurai.sipgate.net/RPC2';

my %tokens;
my %sessions;

my $OKAY = "OK\0\n";
my $FAILED = "FAILED\0\n";

Server::spawn('/var/run/smsotp_socket');
$poe_kernel->run();
exit 0;

package Server;
use POE::Session;
use Socket;

sub
spawn
{
        my $rendezvous = shift;
        POE::Session->create(
                inline_states => {
                        _start     => \&server_started,
                        got_client => \&server_accepted,
                        got_error  => \&server_error,
                },
                heap => {rendezvous => $rendezvous,},
        );
}

sub
server_started
{
        my ($kernel, $heap) = @_[KERNEL, HEAP];
        unlink $heap->{rendezvous} if -e $heap->{rendezvous};
        $heap->{server} = POE::Wheel::SocketFactory->new(
                SocketDomain => PF_UNIX,
                BindAddress  => $heap->{rendezvous},
                SuccessEvent => 'got_client',
                FailureEvent => 'got_error',
        );
}

sub
server_error
{
        my ($heap, $syscall, $errno, $error) = @_[HEAP, ARG0 .. ARG2];
        $error = "Normal disconnection." unless $errno;
        warn "Server socket encountered $syscall error $errno: $error\n";
        delete $heap->{server};
}

sub
server_accepted
{
        my $client_socket = $_[ARG0];
        ServerSession::spawn($client_socket);
}

package ServerSession;
use POE::Session;
use Mail::Mailer;
use Frontier::Client;

sub
spawn
{
        my $socket = shift;
        POE::Session->create(
                inline_states => {
                        _start           => \&server_session_start,
                        got_client_input => \&server_session_input,
                        got_client_error => \&server_session_error,
                },
                args => [$socket],
        );
}

sub
server_session_start
{
        my ($heap, $socket) = @_[HEAP, ARG0];
        $heap->{client} = POE::Wheel::ReadWrite->new(
                Handle     => $socket,
                InputEvent => 'got_client_input',
                ErrorEvent => 'got_client_error',
        );

        $heap->{client}->put("HELLO\0\n");
}

sub
send_email
{
        my %args = @_;

        my $mailer = Mail::Mailer->new('sendmail');
        $mailer->open({
                        From => 'otp@glanzmann.de',
                        To => $args{to},
                        Subject => "One time password",
                        });
        print $mailer $args{otp};
        $mailer->close();
}

sub
send_sms
{
        my %args = @_;

        my $xmlrpc_client = Frontier::Client->new('url' => $sipgateurl);
        my $xmlrpc_result = $xmlrpc_client->call("samurai.ClientIdentify", {
                ClientName => 'sipgateAPI-sms.pl',
                ClientVersion => '1.0',
                ClientVendor => 'indigo networks GmbH'
        });

        if ($xmlrpc_result->{'StatusCode'} != 200) {
                return; # catch error
        }

        $xmlrpc_result = $xmlrpc_client->call("samurai.SessionInitiate", {RemoteUri => "sip:$args{to}\@sipgate.net", TOS => "text", Content => $args{otp}});

        if ($xmlrpc_result->{'StatusCode'} != 200) {
                return; # catch error
        }
}

sub
reply_ok
{
        my $session = shift || die;

        return 0 unless exists($sessions{$session}->{user});
        return 0 unless exists($sessions{$session}->{otp});
        return 0 unless exists($sessions{$session}->{id});

        return 0 unless exists($tokens{$sessions{$session}->{user}}->{id});
        return 0 unless exists($tokens{$sessions{$session}->{user}}->{otp});
        return 0 unless exists($tokens{$sessions{$session}->{user}}->{time});

        return 0 unless ($sessions{$session}->{otp} eq $tokens{$sessions{$session}->{user}}->{otp});
        return 0 unless ($sessions{$session}->{id} eq $tokens{$sessions{$session}->{user}}->{id});

        return 0 unless ((time() - $tokens{$sessions{$session}->{user}}->{time}) < $otp_lifetime);

        return 1;
}

sub
server_session_input
{
        my ($session, $heap, $input) = @_[SESSION, HEAP, ARG0];

        if ($input =~ /^generate otp for ([\w\d]+)/) {
                my $user = $1;

                if (exists($users{$user})) {
                        $tokens{$user}->{id} = int(1 + rand(9999999999));
                        $tokens{$user}->{otp} = sprintf("%05d", int(1 + rand(99999)));
                        $tokens{$user}->{time} = time;

                        if (exists($users{$user}->{email})) {
                                send_email(to => $users{$user}->{email}, otp => $tokens{$user}->{otp});
                        }

                        if (exists($users{$user}->{mobile})) {
                                send_sms(to => $users{$user}->{mobile}, otp => $tokens{$user}->{otp});
                        }
                        $heap->{client}->put($tokens{$user}->{id} . "\0\n");

                } else {
                        $heap->{client}->put($FAILED);
                }

        } elsif ($input =~ /^check otp for ([\w\d]+)/) {
                $sessions{$session}->{user} = $1;
                $heap->{client}->put($OKAY);

        } elsif ($input =~ /^user otp is ([\w\d]+)/) {
                $sessions{$session}->{otp} = $1;
                $heap->{client}->put($OKAY);

        } elsif ($input =~ /^otp id is ([\w\d_-]+)/) {
                $sessions{$session}->{id} = $1;
                $heap->{client}->put($OKAY);

        } elsif ($input =~ /^get check result/) {
                if (reply_ok($session)) {
                        $heap->{client}->put($OKAY);
                } else {
                        $heap->{client}->put($FAILED);
                }

                delete($tokens{$sessions{$session}->{user}});

                delete ($sessions{$session});

        } elsif ($input =~ /^quit/) {
                $heap->{client}->put($OKAY);
                delete ($sessions{$session});
                delete $heap->{client};

        } else {
                $heap->{client}->put($FAILED);
        }
}

sub
server_session_error
{
        my ($heap, $syscall, $errno, $error) = @_[HEAP, ARG0 .. ARG2];
        $error = "Normal disconnection." unless $errno;
        warn "Server session encountered $syscall error $errno: $error\n";
        delete $heap->{client};
}
