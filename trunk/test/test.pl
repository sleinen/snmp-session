#!/usr/local/bin/perl -w
# Minimal useful application of the SNMP package.
# Author: Simon Leinen  <simon@lia.di.epfl.ch>
# RCS $Header: /home/leinen/CVS/SNMP_Session/test/test.pl,v 1.17 2003-05-29 16:39:48 leinen Exp $
######################################################################
# This application sends a get request for three fixed MIB-2 variable
# instances (sysDescr.0, sysContact.0 and ipForwarding.0) to a given
# host.  The hostname and community string can be given as
# command-line arguments.
######################################################################

require 5;

use SNMP_Session;
use BER;
use strict;

### Prototypes
sub usage();
sub snmp_get($@);

$SNMP_Session::suppress_warnings = 1;

my $hostname = shift @ARGV || &usage;
my $community = shift @ARGV || 'public';
my $ipv4_only_p = 0;

usage () if $#ARGV >= 0;

my %ugly_oids = qw(sysDescr.0	1.3.6.1.2.1.1.1.0
		sysContact.0	1.3.6.1.2.1.1.4.0
		sysUptime.0	1.3.6.1.2.1.1.3.0
		ipForwarding.0	1.3.6.1.2.1.4.1.0
		);
my %pretty_oids;

foreach (keys %ugly_oids) {
    $ugly_oids{$_} = encode_oid (split (/\./, $ugly_oids{$_}));
    $pretty_oids{$ugly_oids{$_}} = $_;
}

srand();
my $session = SNMP_Session->open ($hostname, $community, 161,
				  undef, undef, undef, undef, $ipv4_only_p)
    or die "Couldn't open SNMP session to $hostname: $SNMP_Session::errmsg";
snmp_get ($session, qw(sysDescr.0 sysContact.0 sysUptime.0 ipForwarding.0));
$session->close ();
1;

sub snmp_get ($@) {
    my($session, @oids) = @_;
    my($response, $bindings, $binding, $value, $oid);

    grep ($_ = $ugly_oids{$_}, @oids);

    if ($session->get_request_response (@oids)) {
	$response = $session->pdu_buffer;
	($bindings) = $session->decode_get_response ($response);

	while ($bindings ne '') {
	    ($binding,$bindings) = decode_sequence ($bindings);
	    ($oid,$value) = decode_by_template ($binding, "%O%@");
	    print $pretty_oids{$oid}," => ",
	    pretty_print ($value), "\n";
	}
    } else {
	warn "SNMP problem: $SNMP_Session::errmsg\n";
    }
}

sub usage () {
    die "usage: $0 hostname [community]";
}
