#!/usr/bin/perl
#
# Copyright (C) 2008 Sky Network Services.
# Copyright (C) 2022 Network RADIUS.
#
# This program is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
use strict;
use warnings;

use threads;
use threads::shared;

use Net::Radius::Packet;
use Net::Radius::Dictionary;
use NetSNMP::agent qw/:all/;
use NetSNMP::ASN qw/:all/;
use Socket qw(inet_ntop);
use IO::Socket::INET;
use Digest::HMAC_MD5;
use Log::Log4perl qw/:easy/;
#use Data::Dumper;
#$Data::Dumper::Indent = 1;
#$Data::Dumper::Sortkeys = 1;
#$| = 1;

my $cfg = {
    snmp => {
        agent => {
            Name => 'freeradius-snmp',
            AgentX => 1,
        },
        oid_root => '1.3.6.1.2.1.67',
        oid_sub => {
            1 => [qw/auth proxyauth/],
            2 => [qw/acct proxyacct/],
        },
    },

    radius => {
        host => 'localhost',
        port => 18121,
        secret => 'adminsecret',
#        dictionary => '../radiusd/share/dictionary',
        dictionary => 'dictionary.hacked',
        refresh_rate => 20,
    },

    log => {
        level  => $WARN,   # $DEBUG, $ERROR, etc.
        layout => '%d{ISO8601} <%p> (%L) %m%n',
        file   => 'STDERR'
    },

    clients => 1,    # Or 0 to disable
};

Log::Log4perl->easy_init($cfg->{log});

INFO 'starting';
my $running :shared;
my %snmp_data :shared;
my @snmp_data_k :shared;
my %snmp_next :shared;

INFO 'initializing snmp';
my $agent = new NetSNMP::agent(%{$cfg->{snmp}->{agent}});

radius_stats_init();
$running = 1;

$SIG{INT} = sub {
    INFO 'stopping';
    $running = 0;
};

#
#  Background updater thread
#
INFO 'launching radius client thread';
threads->create(\&radius_updater);

#
#  We export only the radiusAuthServ and radiusAccServ subtree
#
$agent->register(
    $cfg->{snmp}->{agent}->{Name},
    $cfg->{snmp}->{oid_root}.'.'.$_, \&snmp_handler) or die
  foreach keys %{$cfg->{snmp}->{oid_sub}};

INFO 'entering client main loop';
$agent->agent_check_and_process(1) while $running;

$agent->shutdown();

$_->join() for threads->list();


#
#  Initialize common radius client stuff
#
sub radius_stats_init {
    our ( $d, $s, $rid );

    $d = new Net::Radius::Dictionary;
    $d->readfile($cfg->{radius}->{dictionary});
    srand ($$ ^ time);
    $rid = int rand 255;

    $s = new IO::Socket::INET(
        PeerHost => $cfg->{radius}->{host},
        PeerPort => $cfg->{radius}->{port},
        Proto => 'udp',
        Timeout => 5) or die;

}

#
#  Build server status packet, send it, fetch and parse the result
#
sub radius_stats_get {
    my ($type, %args) = @_;

    our ($d, $s, $rid);

    my $p_req = new Net::Radius::Packet $d;
    $p_req->set_code('Status-Server');
    $p_req->set_vsattr('FreeRADIUS', 'FreeRADIUS-Statistics-Type', $type);
    $p_req->set_vsattr('FreeRADIUS', $_, $args{$_}) foreach keys %args;

    #
    #  Update id
    #
    $p_req->set_identifier($rid++);
    $p_req->set_authenticator(pack 'C*', map { int rand 255 } 0..15);

    #
    #  Recalc authenticator
    #
    $p_req->set_attr('Message-Authenticator', "\0"x16, 1);
    $p_req->set_attr('Message-Authenticator', Digest::HMAC_MD5::hmac_md5($p_req->pack, $cfg->{radius}->{secret}), 1);

    #
    #  Send brand new and shiny request
    #
    $s->send($p_req->pack) or die;

    my $p_data;
    if (defined $s->recv($p_data, 2048)) {
        my $p_res = new Net::Radius::Packet $d, $p_data;

        my %response =  map {
            $_ => $p_res->vsattr($d->vendor_num('FreeRADIUS'), $_)->[0]
        } $p_res->vsattributes($d->vendor_num('FreeRADIUS'));
        return \%response;

    }
    else {
        warn "no answer, $!\n";
        return undef;
    }

}

#
#  Wrappers for specific types of stats
#
sub radius_stats_get_global { return radius_stats_get(0x1f); }
sub radius_stats_get_client { return radius_stats_get(0x23, 'FreeRADIUS-Stats-Client-Number' => $_[0]); }

#
#  Main loop of thread fetching status from freeradius server
#
sub radius_updater {

    while ($running) {
        INFO 'fetching new data';
        my $main_stat = radius_stats_get_global();

        if (defined $main_stat) {
            my @clients_stat = ();

            if ($cfg->{clients}) {
                my $client_id = 0;

                while (1) {
                    my $client_stat = radius_stats_get_client($client_id);
                    last unless exists $client_stat->{'FreeRADIUS-Stats-Client-IP-Address'} || exists $client_stat->{'FreeRADIUS-Stats-Client-IPv6-Address'};
                    push @clients_stat, $client_stat;
                    $client_id += 1;
                }
            }

            INFO 'got data, updating stats';
            radius_snmp_stats($main_stat, \@clients_stat);

        }
        else {
            WARN 'problem with fetching data';
        }

        INFO 'stats updated, sleeping';
        my $now = time;
        my $next_stats_time = $now + $cfg->{radius}->{refresh_rate};
        do {
            sleep 1;
            $now = time;
        } while ($now < $next_stats_time && $running);

    }

}

#
#  Helper to get a dotted string from NetSNMP::OID
#
sub oid_s { return join '.', $_[0]->to_array; }

#
#  Handler for snmp requests from master agent
#
sub snmp_handler {
    DEBUG 'got new request';
    my ($handler, $registration_info, $request_info, $requests) = @_;

    lock %snmp_data;
    lock @snmp_data_k;
    lock %snmp_next;

    for (my $request = $requests; $request; $request = $request->next()) {
        INFO 'request type '.$request_info->getMode.' for oid: '.oid_s($request->getOID);

        if ($request_info->getMode == MODE_GET) {
            my $oid_s = oid_s($request->getOID);
            if (exists $snmp_data{$oid_s}) {
                $request->setValue($snmp_data{$oid_s}->[0], ''.$snmp_data{$oid_s}->[1]);
            }

        }
        elsif ($request_info->getMode == MODE_GETNEXT) {

            #
            #  Do a fast lookup if we can...
            #
            my $oid = $snmp_next{oid_s($request->getOID)};

            #
            #  ... otherwise take the slow route
            #
            unless (defined $oid) {
                foreach ( @snmp_data_k ) {
                    #the keys is sorted in ascending order, so we are looking for
                    #first value bigger than one in request
                    if ($request->getOID < NetSNMP::OID->new($_)) {
                        $oid = $_;
                        last;
                    }
                }
            }

            next unless $oid;

            $request->setValue($snmp_data{$oid}->[0], ''.$snmp_data{$oid}->[1]);
            $request->setOID($oid);

        }
        else {
            $request->setError($request_info, SNMP_ERR_READONLY);  # No write support
        }
    }
    DEBUG 'finished processing the request';
}

#
#  Init part of subtree for handling radius AUTH statistics
#
sub radius_snmp_stats_init_auth {
    my ($snmp_data_n, $oid, $clients) = @_;

    @{$snmp_data_n->{$oid.'.1.1.1.1'}  = &share([])} = (ASN_OCTET_STR, '');     # radiusAuthServIdent
    @{$snmp_data_n->{$oid.'.1.1.1.2'}  = &share([])} = (ASN_TIMETICKS, 0);      # radiusAuthServUpTime
    @{$snmp_data_n->{$oid.'.1.1.1.3'}  = &share([])} = (ASN_TIMETICKS, 0);      # radiusAuthServResetTime
    @{$snmp_data_n->{$oid.'.1.1.1.4'}  = &share([])} = (ASN_INTEGER, 0);        # radiusAuthServConfigReset
    @{$snmp_data_n->{$oid.'.1.1.1.5'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalAccessRequests
    @{$snmp_data_n->{$oid.'.1.1.1.6'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalInvalidRequests
    @{$snmp_data_n->{$oid.'.1.1.1.7'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalDupAccessRequests
    @{$snmp_data_n->{$oid.'.1.1.1.8'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalAccessAccepts
    @{$snmp_data_n->{$oid.'.1.1.1.9'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalAccessRejects
    @{$snmp_data_n->{$oid.'.1.1.1.10'} = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalAccessChallenges
    @{$snmp_data_n->{$oid.'.1.1.1.11'} = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalMalformedAccessRequests
    @{$snmp_data_n->{$oid.'.1.1.1.12'} = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalBadAuthenticators
    @{$snmp_data_n->{$oid.'.1.1.1.13'} = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalPacketsDropped
    @{$snmp_data_n->{$oid.'.1.1.1.14'} = &share([])} = (ASN_COUNTER, 0);        # radiusAuthServTotalUnknownTypes

    #
    #  radiusAuthClientExtTable
    #
    for (1 .. scalar @$clients) {

        my $addrtype;
        my $addr;
        if (exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'}) {
                $addrtype = 1;
                $addr = $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'};
        }
        elsif (exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'}) {
                $addrtype = 2;
                $addr = inet_ntop(AF_INET6, $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'});
        }
        else {
                next;
        }

        @{$snmp_data_n->{$oid.'.1.1.1.16.1.1.'.$_}  = &share([])} = (ASN_INTEGER, $_);        # radiusAuthClientExtIndex
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.2.'.$_}  = &share([])} = (ASN_INTEGER, $addrtype); # radiusAuthClientInetAddressType
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.3.'.$_}  = &share([])} = (ASN_OCTET_STR, $addr);   # radiusAuthClientInetAddress
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.4.'.$_}  = &share([])} = (ASN_OCTET_STR, $clients->[$_-1]->{'FreeRADIUS-Stats-Client-Number'});        # radiusAuthClientExtID
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.5.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtAccessRequests
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.6.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtDupAccessRequests
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.7.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtAccessAccepts
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.8.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtAccessRejects
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.9.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtAccessChallenges
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.10.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtMalformedAccessRequests
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.11.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtBadAuthenticators
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.12.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtPacketsDropped
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.13.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAuthServExtUnknownTypes
        @{$snmp_data_n->{$oid.'.1.1.1.16.1.14.'.$_} = &share([])} = (ASN_TIMETICKS, 0);       # radiusAuthServerCounterDiscontinuity

    }
}

#
#  Init part of subtree for handling radius ACCT statistics
#
sub radius_snmp_stats_init_acct {
    my ( $snmp_data_n, $oid, $clients ) = @_;

    @{$snmp_data_n->{$oid.'.1.1.1.1'}  = &share([])} = (ASN_OCTET_STR, '');     # radiusAccServIdent
    @{$snmp_data_n->{$oid.'.1.1.1.2'}  = &share([])} = (ASN_TIMETICKS, 0);      # radiusAccServUpTime
    @{$snmp_data_n->{$oid.'.1.1.1.3'}  = &share([])} = (ASN_TIMETICKS, 0);      # radiusAccServResetTime
    @{$snmp_data_n->{$oid.'.1.1.1.4'}  = &share([])} = (ASN_INTEGER, 0);        # radiusAccServConfigReset
    @{$snmp_data_n->{$oid.'.1.1.1.5'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalRequests
    @{$snmp_data_n->{$oid.'.1.1.1.6'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalInvalidRequests
    @{$snmp_data_n->{$oid.'.1.1.1.7'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalDupRequests
    @{$snmp_data_n->{$oid.'.1.1.1.8'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalResponses
    @{$snmp_data_n->{$oid.'.1.1.1.9'}  = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalMalformedRequests
    @{$snmp_data_n->{$oid.'.1.1.1.10'} = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalBadAuthenticators
    @{$snmp_data_n->{$oid.'.1.1.1.11'} = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalPacketsDropped
    @{$snmp_data_n->{$oid.'.1.1.1.12'} = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalNoRecords
    @{$snmp_data_n->{$oid.'.1.1.1.13'} = &share([])} = (ASN_COUNTER, 0);        # radiusAccServTotalUnknownTypes

    #
    #  radiusAccClientExtTable
    #
    for (1 .. scalar @$clients) {

        my $addrtype;
        my $addr;
        if (exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'}) {
                $addrtype = 1;
                $addr = $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'};
        }
        elsif (exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'}) {
                $addrtype = 2;
                $addr = inet_ntop(AF_INET6, $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'});
        }
        else {
                next;
        }

        @{$snmp_data_n->{$oid.'.1.1.1.15.1.1.'.$_}  = &share([])} = (ASN_INTEGER, $_);        # radiusAccClientExtIndex
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.2.'.$_}  = &share([])} = (ASN_INTEGER, $addrtype); # radiusAccClientInetAddressType
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.3.'.$_}  = &share([])} = (ASN_OCTET_STR, $addr);   # radiusAccClientInetAddress
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.4.'.$_}  = &share([])} = (ASN_OCTET_STR, $clients->[$_-1]->{'FreeRADIUS-Stats-Client-Number'});        # radiusAccClientExtID
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.5.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtPacketsDropped
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.6.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtRequests
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.7.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtDupRequests
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.8.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAccServResponses
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.9.'.$_}  = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtBadAuthenticators
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.10.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtMalformedRequests
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.11.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtNoRecords
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.12.'.$_} = &share([])} = (ASN_COUNTER, 0);         # radiusAccServExtUnknownTypes
        @{$snmp_data_n->{$oid.'.1.1.1.15.1.13.'.$_} = &share([])} = (ASN_TIMETICKS, 0);       # radiusAccServerCounterDiscontinuity

    }
}

#
#  Fill part of subtree with data from radius AUTH statistics
#
sub radius_snmp_stats_fill_auth {
    my ($snmp_data_n, $oid, $prefix, $main, $clients) = @_;

    my $time = time;

    $snmp_data_n->{$oid.'.1.1.1.1'}->[1]  = 'snmp(over)radius';
    $snmp_data_n->{$oid.'.1.1.1.2'}->[1]  = ($time - $main->{'FreeRADIUS-Stats-Start-Time'})*100;
    $snmp_data_n->{$oid.'.1.1.1.3'}->[1]  = ($time - $main->{'FreeRADIUS-Stats-HUP-Time'})*100;
    $snmp_data_n->{$oid.'.1.1.1.4'}->[1]  = 0;
    $snmp_data_n->{$oid.'.1.1.1.5'}->[1]  += $main->{$prefix.'Access-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.6'}->[1]  += $main->{$prefix.'Auth-Invalid-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.7'}->[1]  += $main->{$prefix.'Auth-Duplicate-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.8'}->[1]  += $main->{$prefix.'Access-Accepts'};
    $snmp_data_n->{$oid.'.1.1.1.9'}->[1]  += $main->{$prefix.'Access-Rejects'};
    $snmp_data_n->{$oid.'.1.1.1.10'}->[1] += $main->{$prefix.'Access-Challenges'};
    $snmp_data_n->{$oid.'.1.1.1.11'}->[1] += $main->{$prefix.'Auth-Malformed-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.12'}->[1] += 0;
    $snmp_data_n->{$oid.'.1.1.1.13'}->[1] += $main->{$prefix.'Auth-Dropped-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.14'}->[1] += $main->{$prefix.'Auth-Unknown-Types'};

    for (1 .. scalar @$clients) {
        next unless exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'} || exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'};
        $snmp_data_n->{$oid.'.1.1.1.16.1.5.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Access-Requests'}         || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.6.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Auth-Duplicate-Requests'} || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.7.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Access-Accepts'}          || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.8.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Access-Rejects'}          || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.9.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Access-Challenges'}       || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.10.'.$_}->[1] += $clients->[$_-1]->{$prefix.'Auth-Malformed-Requests'} || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.11.'.$_}->[1] += 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.12.'.$_}->[1] += $clients->[$_-1]->{$prefix.'Auth-Dropped-Requests'}   || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.13.'.$_}->[1] += $clients->[$_-1]->{$prefix.'Auth-Unknown-Types'}      || 0;
        $snmp_data_n->{$oid.'.1.1.1.16.1.14.'.$_}->[1] += 0;
    }
}

#
#  Fill part of subtree with data from radius ACCT statistics
#
sub radius_snmp_stats_fill_acct {
    my ( $snmp_data_n, $oid, $prefix, $main, $clients ) = @_;

    my $time = time;

    $snmp_data_n->{$oid.'.1.1.1.1'}->[1]  = 'snmp(over)radius';
    $snmp_data_n->{$oid.'.1.1.1.2'}->[1]  = ($time - $main->{'FreeRADIUS-Stats-Start-Time'})*100;
    $snmp_data_n->{$oid.'.1.1.1.3'}->[1]  = ($time - $main->{'FreeRADIUS-Stats-HUP-Time'})*100;
    $snmp_data_n->{$oid.'.1.1.1.4'}->[1]  = 0;
    $snmp_data_n->{$oid.'.1.1.1.5'}->[1]  += $main->{$prefix.'Accounting-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.6'}->[1]  += $main->{$prefix.'Acct-Invalid-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.7'}->[1]  += $main->{$prefix.'Acct-Duplicate-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.8'}->[1]  += $main->{$prefix.'Accounting-Responses'};
    $snmp_data_n->{$oid.'.1.1.1.9'}->[1]  += $main->{$prefix.'Acct-Malformed-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.10'}->[1] += 0;
    $snmp_data_n->{$oid.'.1.1.1.11'}->[1] += $main->{$prefix.'Acct-Dropped-Requests'};
    $snmp_data_n->{$oid.'.1.1.1.12'}->[1] += 0;
    $snmp_data_n->{$oid.'.1.1.1.13'}->[1] += $main->{$prefix.'Acct-Unknown-Types'};

    for (1 .. scalar @$clients) {
        next unless exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IP-Address'} || exists $clients->[$_-1]->{'FreeRADIUS-Stats-Client-IPv6-Address'};
        $snmp_data_n->{$oid.'.1.1.1.15.1.5.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Acct-Dropped-Requests'}   || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.6.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Accounting-Requests'}     || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.7.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Acct-Duplicate-Requests'} || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.8.'.$_}->[1]  += $clients->[$_-1]->{$prefix.'Accounting-Responses'}    || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.9.'.$_}->[1]  += 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.10.'.$_}->[1] += $clients->[$_-1]->{$prefix.'Acct-Malformed-Requests'} || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.11.'.$_}->[1] += 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.12.'.$_}->[1] += $clients->[$_-1]->{$prefix.'Acct-Unknown-Types'}      || 0;
        $snmp_data_n->{$oid.'.1.1.1.15.1.13.'.$_}->[1] += 0;
    }
}

#
#  Update statistics
#
sub radius_snmp_stats {
    my ($main, $clients) = @_;

    my %snmp_data_n;

    #
    #  We have to go through all oid's
    #
    foreach my $oid_s ( keys %{$cfg->{snmp}->{oid_sub}} ) {

        #
        #  We're rebuilding the tree for data. We could do it only once, but it
        #  will change when we will start handling more dynamic tree (clients)
        #
        my %types = map { $_ => 1 } map { /(?:proxy)?(\w+)/; $1 } @{$cfg->{snmp}->{oid_sub}->{$oid_s}};
        WARN 'two conflicting types for oid '.$oid_s if scalar keys %types > 1;

        if ((keys %types)[0] eq 'auth') {
            radius_snmp_stats_init_auth(\%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s, $clients);
        }
        elsif ( (keys %types)[0] eq 'acct' ) {
            radius_snmp_stats_init_acct(\%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s, $clients);
        }
        else {
            WARN 'unknown subtree type '.(keys %types)[0];
        }

        #
        #  Refill the statistics
        #
        foreach my $type (@{$cfg->{snmp}->{oid_sub}->{$oid_s}}) {
            if ($type eq 'auth') {
                radius_snmp_stats_fill_auth(
                    \%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s,
                    'FreeRADIUS-Total-', $main, $clients);
            }
            elsif ($type eq 'proxyauth') {
                radius_snmp_stats_fill_auth(
                    \%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s,
                    'FreeRADIUS-Total-Proxy-', $main, $clients);
            }
            elsif ($type eq 'acct') {
                radius_snmp_stats_fill_acct(
                    \%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s,
                    'FreeRADIUS-Total-', $main, $clients);
            }
            elsif ($type eq 'proxyacct') {
                radius_snmp_stats_fill_acct(
                    \%snmp_data_n, $cfg->{snmp}->{oid_root}.'.'.$oid_s,
                    'FreeRADIUS-Total-Proxy-', $main, $clients);
            }
            else {
                WARN 'unknown subtree type '.$type;
            }

        }
    }

    #
    #  Copy the rebuilt tree to the shared variables
    #
    my @k = map { oid_s($_) } sort { $a <=> $b } map { NetSNMP::OID->new($_) } keys %snmp_data_n;
    my %snmp_next_n = ();
    $snmp_next_n{$k[$_]} = $k[$_+1] for (0 .. $#k-1);

    lock %snmp_data;
    lock @snmp_data_k;
    lock %snmp_next;

    %snmp_data = %snmp_data_n;
    @snmp_data_k = @k;
    %snmp_next = %snmp_next_n;

}

=head1 NAME

freeradius snmp agentx subagent

=head1 VERSION

=head1 SYNOPSIS

make sure snmpd is agentx master (snmpd.conf):
master agentx

run the script (no demonizing support yet):

./freeradius-snmp.pl

then you can walk the tree (default oid):

snmpbulkwalk -On -v2c -cpublic localhost .1.3.6.1.2.1.67

if per-client stats collection is enabled then you can do the following:

snmptable -v2c -cpublic localhost .1.3.6.1.2.1.67.1.1.1.1.16
snmptable -v2c -cpublic localhost .1.3.6.1.2.1.67.2.1.1.1.15

=head1 DESCRIPTION

=head1 DEPENDENCIES

Net-Radius (either 1.56 + net-radius-freeradius-dictionary.diff to use freeradius dictionaries
  or vanilla upstream one + dictionary.hacked)
NetSNMP perl modules (available with net-snmp distribution)
Digest::HMAC
Log::Log4perl

=head1 AUTHOR

Stanislaw Sawa <stanislaw.sawa(at)sns.bskyb.com>

=head1 COPYRIGHT

Copyright (C) 2008 Sky Network Services.
Copyright (C) 2022 Network RADIUS.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
