package SNMP_util;

require 5.002;

use strict;
use vars qw(@ISA @EXPORT $VERSION);
use Exporter;

use BER "0.54";
use SNMP_Session "0.56";
use Socket;

$VERSION = '0.54';

@ISA = qw(Exporter);

@EXPORT = qw(snmpget snmpgetnext snmpwalk snmpset snmptrap);

%SNMP_util::OIDS = 
  ('sysDescr' => '1.3.6.1.2.1.1.1.0',
   'sysContact' => '1.3.6.1.2.1.1.4.0',
   'sysName' => '1.3.6.1.2.1.1.5.0',
   'sysLocation' => '1.3.6.1.2.1.1.6.0',
   'sysUptime' => '1.3.6.1.2.1.1.3.0',
   'ifNumber' =>  '1.3.6.1.2.1.2.1.0',
   ###################################
   # add the ifNumber ....
   'ifDescr' => '1.3.6.1.2.1.2.2.1.2',
   'ifType' => '1.3.6.1.2.1.2.2.1.3',
   'ifIndex' => '1.3.6.1.2.1.2.2.1.1',
   'ifInErrors' => '1.3.6.1.2.1.2.2.1.14',
   'ifOutErrors' => '1.3.6.1.2.1.2.2.1.20',
   'ifInOctets' => '1.3.6.1.2.1.2.2.1.10',
   'ifOutOctets' => '1.3.6.1.2.1.2.2.1.16',
   'ifInDiscards' => '1.3.6.1.2.1.2.2.1.13',
   'ifOutDiscards' => '1.3.6.1.2.1.2.2.1.19',
   'ifInUcastPkts' => '1.3.6.1.2.1.2.2.1.11',
   'ifOutUcastPkts' => '1.3.6.1.2.1.2.2.1.17',
   'ifInNUcastPkts' => '1.3.6.1.2.1.2.2.1.12',
   'ifOutNUcastPkts' => '1.3.6.1.2.1.2.2.1.18',
   'ifInUnknownProtos' => '1.3.6.1.2.1.2.2.1.15',
   'ifOutQLen' => '1.3.6.1.2.1.2.2.1.21',
   'ifSpeed' => '1.3.6.1.2.1.2.2.1.5', 
   # up 1, down 2, testing 3
   'ifOperStatus' => '1.3.6.1.2.1.2.2.1.8',             
   'ifAdminStatus' => '1.3.6.1.2.1.2.2.1.7',  
   # up = 1 else 0;
   'ifOperHack' => '1.3.6.1.2.1.2.2.1.8',             
   'ifAdminHack' => '1.3.6.1.2.1.2.2.1.7',  
    #frame relay stuff ... see the docs for explanations
    'frInOctets' => '1.3.6.1.2.1.10.32.2.1.9',
    'frOutOctets' => '1.3.6.1.2.1.10.32.2.1.7',
  );

undef $SNMP_util::Host;
undef $SNMP_util::Session;

srand(time|$$);

### Prototypes
sub snmpget (@);
sub snmpgetnext (@);
sub snmpopen (@);
sub snmpwalk (@);
sub snmpset (@);
sub snmptrap (@);
sub toOID (@);

sub version () { $VERSION; }

#
# Start an snmp session
#
sub snmpopen (@) {
  my($host) = @_;
  my($nhost,$port,$community);

  $community = "public";
  $port = 161;

  ($community, $host) = split('@', $host, 2) if ($host =~ /\@/);
  ($host, $port) = split(':', $host, 2) if ($host =~ /:/);
  $nhost = "$community\@$host:$port";

  if ((!defined($SNMP_util::Session))
    || ($SNMP_util::Host ne $nhost))
  {
    if (defined($SNMP_util::Session))
    {
      $SNMP_util::Session->close ();    
      undef $SNMP_util::Session;
      undef $SNMP_util::Host;
    }
    $SNMP_util::Session = SNMP_Session->open($host,$community,$port);
    $SNMP_util::Host = $nhost if defined($SNMP_util::Session);
  }
  return $SNMP_util::Session;
}


#
# A restricted snmpget.
#
sub snmpget (@) {
  my($host,@vars) = @_;
  my(@enoid, $var,$response, $bindings, $binding, $value,$oid,@retvals);

  @enoid = &toOID(@vars);

  my $session;
  $session = &snmpopen($host);
  if (! defined($session)) {
    warn "SNMPGET Problem for $host\n";
    return undef;
  }

  if ($session->get_request_response(@enoid)) {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response ($response);
    while ($bindings) {
      ($binding,$bindings) = decode_sequence ($bindings);
      ($oid,$value) = decode_by_template ($binding, "%O%@");
      my $tempo = pretty_print($value);
      push @retvals,  $tempo;
    }
    return (@retvals);
  }
  $var = join(' ', @vars);
  warn "SNMPGET Problem for $var on $host\n";
  return undef;
}

#
# A restricted snmpgetnext.
#
sub snmpgetnext (@) {
  my($host,@vars) = @_;
  my(@enoid, $var,$response, $bindings, $binding, $value,$upoid,$oid,@retvals);
  my($noid, $ok);

  @enoid = &toOID(@vars);

  my $session;
  $session = &snmpopen($host);
  if (! defined($session)) {
    warn "SNMPGETNEXT Problem for $host\n";
    return undef;
  }

  undef @vars;
  undef @retvals;
  foreach $noid (@enoid)
  {
    $upoid = pretty_print($noid);
    push(@vars, $upoid);
  }
  if ($session->getnext_request_response(@enoid))
  {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response ($response);
    while ($bindings) {
      ($binding,$bindings) = decode_sequence ($bindings);
      ($oid,$value) = decode_by_template ($binding, "%O%@");
      $ok = 0;
      my $tempo = pretty_print($oid);
      foreach $noid (@vars)
      {
	if ($tempo =~ /^$noid\./)
	{
	  $ok = 1;
	  $upoid = $noid;
	  last;
	}
      }
      if ($ok)
      {
	my $tempv = pretty_print($value);
##################################################################
####
#### Don't remove the OID prefix because there could be multiple
#### OID's specified in the 'getnext' call!
####
####	$tempo=~s/^$upoid\.//;
##################################################################
	push @retvals,  "$tempo:$tempv";
      }
    }
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    warn "SNMPGETNEXT Problem for $var on $host\n";
    return undef;
  }
}

#
# A restricted snmpwalk.
#
sub snmpwalk (@) {
  my($host,@vars) = @_;
  my(@enoid, $var,$response, $bindings, $binding, $value,$upoid,$oid,@retvals);
  my($got, @nnoid, $noid, $ok);

  @enoid = toOID(@vars);

  my $session;
  $session = &snmpopen($host);
  if (! defined($session)) {
    warn "SNMPWALK Problem for $host\n";
    return undef;
  }

  $got = 0;
  @nnoid = @enoid;
  undef @vars;
  foreach $noid (@enoid)
  {
    $upoid = pretty_print($noid);
    push(@vars, $upoid);
  }
  while($session->getnext_request_response(@nnoid))
  {
    $got = 1;
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response ($response);
    undef @nnoid;
    while ($bindings) {
      ($binding,$bindings) = decode_sequence ($bindings);
      ($oid,$value) = decode_by_template ($binding, "%O%@");
      $ok = 0;
      my $tempo = pretty_print($oid);
      foreach $noid (@vars)
      {
	if ($tempo =~ /^$noid\./)
	{
	  $ok = 1;
	  $upoid = $noid;
	  last;
	}
      }
      if ($ok)
      {
	push @nnoid,  encode_oid(split(/\./, $tempo));
	my $tempv = pretty_print($value);
	$tempo=~s/^$upoid\.//;
	push @retvals,  "$tempo:$tempv";
      }
    }
    last if ($#nnoid < 0);
  }
  if ($got)
  {
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    warn "SNMPWALK Problem for $var on $host\n";
    return undef;
  }
}

#
# A restricted snmpset.
#
sub snmpset(@) {
    my($host,@vars) = @_;
    my(@enoid, $response, $bindings, $binding);
    my($oid, @retvals, $type, $value);

    while(@vars)
    {
	($oid) = toOID((shift @vars));
	$type  = shift @vars;
	$value = shift @vars;
	if ($type =~ /string/i)
	{
	    $value = encode_string($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /int/i)
	{
	    $value = encode_int($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /oid/i)
	{
	    $value = encode_oid(split(/\./, $value));
	    push @enoid, [$oid,$value];
	}
	else
	{
	    warn "unknown SNMP type: $type\n";
	    return undef;
	}
    }
    my $session;
    $session = &snmpopen($host);
    if (! defined($session))
    {
	warn "SNMPSET Problem for $host\n";
	return undef;
    }
    if ($session->set_request_response(@enoid))
    {
	$response = $session->pdu_buffer;
	($bindings) = $session->decode_get_response ($response);
	while ($bindings)
	{
	    ($binding,$bindings) = decode_sequence ($bindings);
	    ($oid,$value) = decode_by_template ($binding, "%O%@");
	    my $tempo = pretty_print($value);
	    $tempo=~s/\t/ /g;
	    $tempo=~s/\n/ /g;
	    $tempo=~s/^\s+//;
	    $tempo=~s/\s+$//;
	    push @retvals,  $tempo;
	}
	return (@retvals);
    }
    return undef;
}

#
# Send an SNMP trap
#
sub snmptrap(@) {
    my($host,$ent,$agent,$gen,$spec,@vars) = @_;
    my($oid, @retvals, $type, $value);
    my(@enoid);

    if ($agent =~ /^\d+\.\d+\.\d+\.\d+(.*)/ )
    {
	$agent = pack("C*", split /\./, $agent);
    }
    else
    {
	$agent = inet_aton($agent);
    }
    push @enoid, toOID(($ent));
    push @enoid, encode_string($agent);
    push @enoid, encode_int($gen);
    push @enoid, encode_int($spec);
    push @enoid, encode_int(time);
    while(@vars)
    {
	($oid) = toOID((shift @vars));
	$type  = shift @vars;
	$value = shift @vars;
	if ($type =~ /string/i)
	{
	    $value = encode_string($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /int/i)
	{
	    $value = encode_int($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /oid/i)
	{
	    $value = encode_oid(split(/\./, $value));
	    push @enoid, [$oid,$value];
	}
	else
	{
	    warn "unknown SNMP type: $type\n";
	    return undef;
	}
    }
    my $session;
    $host = $host . ':162' if !($host =~ /:/);
    $session = &snmpopen($host);
    if (! defined($session))
    {
	warn "SNMPTRAP Problem for $host\n";
	return undef;
    }
    return($session->trap_request_send(@enoid));
}

#
#  Given an OID in either ASN.1 or mixed text/ASN.1 notation, return an
#  encoded OID.
#
sub toOID(@)
{
    my(@vars) = @_;
    my($oid, $var, @retvar);

    undef @retvar;
    foreach $var (@vars)
    {
	if ($var =~ /^([a-z]+[^\.]*)/i)
	{
	    $oid = $SNMP_util::OIDS{$1};
	    if ($oid) {
		$var =~ s/$1/$oid/;
	    } else {
		warn "Unknown SNMP var $var\n";
		next;
	    }
	}
	print "toOID: $var\n" if $main::DEBUG >5;
	push(@retvar, encode_oid(split(/\./, $var)));
    }
    return @retvar;
}

1;
