#!/logiciels/public/divers/bin/perl5

require 5;

require 'SNMP_Session.pm';
require 'BER.pm';

srand();

%ugly_oids = ( "sysDescr.0" => "1.3.6.1.2.1.1.1.0",
		"sysContact.0" => "1.3.6.1.2.1.1.4.0",
	      "ipForwarding.0" => "1.3.6.1.2.1.4.1.0"
	      );
foreach (keys %ugly_oids) {
    $ugly_oids{$_} = BER::encode_oid (split (/\./, $ugly_oids{$_}));
    $pretty_oids{$ugly_oids{$_}} = $_;
}

$session = SNMP_Session->open ('liasg7', 'public', 161);
for ($i = 0; $i < 10; ++$i) {
    snmp_get ($session, qw(sysDescr sysContact ipForwarding));
}
$session->close ();
1;

sub snmp_get
{
    my($session, @oids) = @_;
    my($response, $bindings, $binding, $value, $oid);
    grep ($_ = $ugly_oids{$_.".0"}, @oids);
    if ($session->get_request_response (@oids)) {
	$response = $session->{pdu_buffer};
	($bindings) = $session->decode_get_response ($response);

	while ($bindings ne '') {
	    ($binding,$bindings) = BER::decode_sequence ($bindings);
	    ($oid,$value) = BER::decode_by_template ($binding, "%O%@");
	    print $pretty_oids{$oid}," => ",
	    BER::pretty_print ($value), "\n";
	}
    } else {
	warn "Response not received.\n";
    }
}
