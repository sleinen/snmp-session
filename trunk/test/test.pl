#!/logiciels/public/divers/bin/perl5
# Minimal useful application of the SNMP package.
# Author: Simon Leinen  <simon@lia.di.epfl.ch>
# RCS $Header: /home/leinen/CVS/SNMP_Session/test/test.pl,v 1.9 1995-07-06 12:55:28 simon Exp $
######################################################################
# This application sends a get request for three fixed MIB-2 variable
# instances (sysDescr.0, sysContact.0 and ipForwarding.0) to a given
# host.  The hostname and community string can be given as
# command-line arguments.
######################################################################

require 5;

require 'SNMP_Session.pm';
use BER;

$hostname = shift @ARGV || &usage;
$community = shift @ARGV || 'public';
&usage if $#ARGV >= 0;

%ugly_oids = ( "sysDescr.0" => "1.3.6.1.2.1.1.1.0",
		"sysContact.0" => "1.3.6.1.2.1.1.4.0",
	      "ipForwarding.0" => "1.3.6.1.2.1.4.1.0"
	      );
foreach (keys %ugly_oids) {
    $ugly_oids{$_} = encode_oid (split (/\./, $ugly_oids{$_}));
    $pretty_oids{$ugly_oids{$_}} = $_;
}

srand();
$session = SNMP_Session->open ('liasg7', 'public', 161);
snmp_get ($session, qw(sysDescr.0 sysContact.0 ipForwarding.0));
$session->close ();
1;

sub snmp_get
{
    my($session, @oids) = @_;
    my($response, $bindings, $binding, $value, $oid);

    grep ($_ = $ugly_oids{$_}, @oids);

    if ($session->get_request_response (@oids)) {
	$response = $session->{pdu_buffer};
	($bindings) = $session->decode_get_response ($response);

	while ($bindings ne '') {
	    ($binding,$bindings) = decode_sequence ($bindings);
	    ($oid,$value) = decode_by_template ($binding, "%O%@");
	    print $pretty_oids{$oid}," => ",
	    pretty_print ($value), "\n";
	}
    } else {
	warn "Response not received.\n";
    }
}

sub usage
{
    die "usage: $0 hostname [community]";
}
