#!/usr/local/bin/perl

use strict;
use BER '0.58';
use SNMP_Session '0.58';

my $trap_receiver = "130.59.10.30";
my $trap_community = "hctiws";
my $trap_session = SNMPv1_Session->open ($trap_receiver, $trap_community, 162);
my $myIpAddress = pack ("CCCC", 208, 151, 198, 211);	# the sender's IP Address
my $start_time = time ;


enterspecific_trap (1);		# enterpriseSpecific Trap
#6;

sub enterspecific_trap ($) {
  my ($if_index) = @_;
 
  my $genericTrap = 6;		# TRAP-TYPE: enterprise
  print "$genericTrap\n";

  my $specificTrap = 2;		# enterpriseSpecific Trap
  print "$specificTrap\n";

  my @pEnterpriseOID = ( 1,3,6,1,4,1,1709,0,4,1000 );	# Trap OID sent

  my @myOID = ( 1,3,6,1,4,1,1709,0,4,1000 );	#Trap Bind Object
  print "@myOID\n";

  my $upTime = ((time - $start_time) / 10);
  print "$upTime\n";
  

  warn "Sending trap failed"
    unless $trap_session->trap_request_send (encode_oid (@myOID),
					     encode_ip_address ($myIpAddress),
					     encode_int ($genericTrap),
					     encode_int ($specificTrap),
					     encode_timeticks ($upTime),
					     [encode_oid (@pEnterpriseOID,$if_index),
					      encode_int ($if_index)]);
print $trap_session;

}
