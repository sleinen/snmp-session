#!/usr/bin/perl

require 'BER.pm';
require 'SNMP_Session.pm';

srand();

$oid_system_sysDescr_0 = BER::encode_oid (1, 3, 6, 1, 2, 1, 1, 1, 0);
$oid_system_sysContact_0 = BER::encode_oid (1, 3, 6, 1, 2, 1, 1, 4, 0);

$session = SNMP_Session->open ('liasg5', 'public', 161);
if ($session->get_request_response ($oid_system_sysDescr_0,
				    $oid_system_sysContact_0)) {
    $response = $session->{pdu_buffer};
    ($bindings) = $session->decode_get_response ($response);

    while ($bindings ne '') {
	($binding,$bindings) = &BER::decode_sequence ($bindings);
	($oid,$value) = &BER::decode_by_template ($binding, "%O%@");
	print (&BER::pretty_print ($oid)," => ",
	       &BER::pretty_print ($value), "\n");
    }
} else {
    warn "Response not received.\n";
}
$session->close ();

require 5;
