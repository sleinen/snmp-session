#!/usr/local/bin/perl -w
###
### Small test program that uses GetNext requests to walk a table.
###

use strict;
use BER;
use SNMP_Session;

my $hostname = $ARGV[0] || 'popocatepetl';
my $community = $ARGV[1] || 'public';

my $session;

die unless ($session = SNMP_Session->open ($hostname, $community, 161));

my @ipAdEntAddr = split ('\.', '1.3.6.1.2.1.4.20.1.1');
my @ipAdEntIfIndex = split ('\.', '1.3.6.1.2.1.4.20.1.2');

my $addr_index = encode_oid (@ipAdEntAddr);
my $if_index_index = encode_oid (@ipAdEntIfIndex);

my @oids = ($addr_index, $if_index_index);
my @next_oids;

my $oid;
my $i;
for (;;) {
    if ($session->getnext_request_response (@oids)) {
	my $response = $session->pdu_buffer;
	my ($bindings, $binding, $oid, $value);

	($bindings) = $session->decode_get_response ($response);
	@next_oids = ();

	## IP address
	($binding,$bindings) = decode_sequence ($bindings);
	($oid,$value) = decode_by_template ($binding, "%O%@");
	last
	    unless BER::encoded_oid_prefix_p ($addr_index, $oid);
	push @next_oids, $oid;
	print pretty_print ($value), ' [',pretty_print ($oid), "]\n";

	## Interface index
	($binding,$bindings) = decode_sequence ($bindings);
	($oid,$value) = decode_by_template ($binding, "%O%@");
	last
	    unless BER::encoded_oid_prefix_p ($if_index_index, $oid);
	push @next_oids, $oid;
	print pretty_print ($value), ' [',pretty_print ($oid), "]\n";

    } else {
	die "No response received.\n";
    }
    @oids = @next_oids;
}

$session->close ();

1;
