package SNMP_util;

require 5.002;

use strict;
use vars qw(@ISA @EXPORT $VERSION);
use Exporter;

use BER "0.58";
use SNMP_Session "0.59";
use Socket;

$VERSION = '0.58';

@ISA = qw(Exporter);

@EXPORT = qw(snmpget snmpgetnext snmpwalk snmpset snmptrap snmpmapOID);

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

my $agent_start_time = time;

undef $SNMP_util::Host;
undef $SNMP_util::Session;
$SNMP_util::Debug = 0;

srand(time|$$);

### Prototypes
sub snmpget (@);
sub snmpgetnext (@);
sub snmpopen (@);
sub snmpwalk (@);
sub snmpset (@);
sub snmptrap (@);
sub toOID (@);
sub snmpmapOID (@);
sub encode_oid_with_errmsg ($);

sub version () { $VERSION; }

#
# Start an snmp session
#
sub snmpopen (@) {
  my($host) = @_;
  my($nhost, $port, $community);
  my($timeout, $retries, $backoff);

  $community = "public";
  $port = 161;

  ($community, $host) = split('@', $host, 2) if ($host =~ /\@/);
  ($host, $port, $timeout, $retries, $backoff) = split(':', $host, 5)
    if ($host =~ /:/);
  $nhost = "$community\@$host:$port";

  if ((!defined($SNMP_util::Session))
    || ($SNMP_util::Host ne $nhost))
  {
    if (defined($SNMP_util::Session))
    {
      $SNMP_util::Session->close();    
      undef $SNMP_util::Session;
      undef $SNMP_util::Host;
    }
    $SNMP_util::Session = SNMP_Session->open($host, $community, $port);
    $SNMP_util::Host = $nhost if defined($SNMP_util::Session);
  }

  if (defined($SNMP_util::Session))
  {
    $SNMP_util::Session->set_timeout($timeout)
      if (defined($timeout) && (length($timeout) > 0));
    $SNMP_util::Session->set_retries($retries)
      if (defined($retries) && (length($retries) > 0));
    $SNMP_util::Session->set_backoff($backoff)
      if (defined($backoff) && (length($backoff) > 0));
  }
  return $SNMP_util::Session;
}


#
# A restricted snmpget.
#
sub snmpget (@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding, $value, $oid, @retvals);
  my $session;

  $session = &snmpopen($host);
  if (!defined($session)) {
    warn "SNMPGET Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = &toOID(@vars);
  return undef unless defined $enoid[0];

  if ($session->get_request_response(@enoid)) {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response($response);
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
      my $tempo = pretty_print($value);
      push @retvals, $tempo;
    }
    return(@retvals);
  }
  $var = join(' ', @vars);
  warn "SNMPGET Problem for $var on $host\n"
    unless ($SNMP_Session::suppress_warnings > 1);
  return undef;
}

#
# A restricted snmpgetnext.
#
sub snmpgetnext (@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding);
  my($value, $upoid, $oid, @retvals);
  my($noid, $ok);
  my $session;

  $session = &snmpopen($host);
  if (!defined($session)) {
    warn "SNMPGETNEXT Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = &toOID(@vars);

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
    ($bindings) = $session->decode_get_response($response);
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
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
	push @retvals, "$tempo:$tempv";
      }
    }
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    warn "SNMPGETNEXT Problem for $var on $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }
}

#
# A restricted snmpwalk.
#
sub snmpwalk (@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding);
  my($value, $upoid, $oid, @retvals);
  my($got, @nnoid, $noid, $ok);
  my $session;

  $session = &snmpopen($host);
  if (!defined($session)) {
    warn "SNMPWALK Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = toOID(@vars);

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
    ($bindings) = $session->decode_get_response($response);
    undef @nnoid;
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
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
	my $tmp = encode_oid_with_errmsg ($tempo);
	return undef unless defined $tmp;
	push @nnoid, $tmp;
	my $tempv = pretty_print($value);
	$tempo=~s/^$upoid\.//;
	push @retvals, "$tempo:$tempv";
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
    warn "SNMPWALK Problem for $var on $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }
}

#
# A restricted snmpset.
#
sub snmpset(@) {
    my($host, @vars) = @_;
    my(@enoid, $response, $bindings, $binding);
    my($oid, @retvals, $type, $value);
    my $session;

    $session = &snmpopen($host);
    if (!defined($session))
    {
	warn "SNMPSET Problem for $host\n"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }

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
	    my $tmp = encode_oid_with_errmsg($value);
	    return undef unless defined $tmp;
	    push @enoid, [$oid,$tmp];
	}
	else
	{
	    warn "unknown SNMP type: $type\n"
		unless ($SNMP_Session::suppress_warnings > 1);
	    return undef;
	}
    }
    if ($session->set_request_response(@enoid))
    {
	$response = $session->pdu_buffer;
	($bindings) = $session->decode_get_response($response);
	while ($bindings)
	{
	    ($binding, $bindings) = decode_sequence($bindings);
	    ($oid, $value) = decode_by_template($binding, "%O%@");
	    my $tempo = pretty_print($value);
	    push @retvals, $tempo;
	}
	return (@retvals);
    }
    return undef;
}

#
# Send an SNMP trap
#
sub snmptrap(@) {
    my($host, $ent, $agent, $gen, $spec, @vars) = @_;
    my($oid, @retvals, $type, $value);
    my(@enoid);
    my $session;

    $host = $host . ':162' if !($host =~ /:/);
    $session = &snmpopen($host);
    if (!defined($session))
    {
	warn "SNMPTRAP Problem for $host\n"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }

    if ($agent =~ /^\d+\.\d+\.\d+\.\d+(.*)/ )
    {
	$agent = pack("C*", split /\./, $agent);
    }
    else
    {
	$agent = inet_aton($agent);
    }
    push @enoid, toOID(($ent));
    push @enoid, encode_ip_address($agent);
    push @enoid, encode_int($gen);
    push @enoid, encode_int($spec);
    push @enoid, encode_timeticks((time-$agent_start_time) * 100);
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
	    my $tmp = encode_oid_with_errmsg($value);
	    return undef unless defined $tmp;
	    push @enoid, [$oid,$tmp];
	}
	else
	{
	    warn "unknown SNMP type: $type\n"
		unless ($SNMP_Session::suppress_warnings > 1);
	    return undef;
	}
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
    my($oid, $var, $tmp, @retvar);

    undef @retvar;
    foreach $var (@vars)
    {
	if ($var =~ /^(([a-z][a-z\d\-]*\.)*([a-z][a-z\d\-]*))/i)
	{
	    $tmp = $&;
	    $oid = $SNMP_util::OIDS{$tmp};
	    if ($oid) {
		$var =~ s/^$tmp/$oid/;
	    } else {
		warn "Unknown SNMP var $var\n"
		    unless ($SNMP_Session::suppress_warnings > 1);
		next;
	    }
	}
	print "toOID: $var\n" if $SNMP_util::Debug;
	$tmp = encode_oid_with_errmsg($var);
	return undef unless defined $tmp;
	push(@retvar, $tmp);
    }
    return @retvar;
}

#
#  Add passed-in text, OID pairs to the OID mapping table.
#
sub snmpmapOID(@)
{
    my(@vars) = @_;
    my($oid, $txt, $ind);

    $ind = 0;
    while($ind <= $#vars)
    {
	$txt = $vars[$ind++];
	next unless($txt =~ /^(([a-z][a-z\d\-]*\.)*([a-z][a-z\d\-]*))$/i);

	$oid = $vars[$ind++];
	next unless($oid =~ /^((\d+.)*\d+)$/);

	$SNMP_util::OIDS{$txt} = $oid;
	print "snmpmapOID: $txt => $oid\n" if $SNMP_util::Debug;
    }
    return undef;
}

sub encode_oid_with_errmsg ($) {
    my ($oid) = @_;
    my $tmp = encode_oid(split(/\./, $oid));
    if (! defined $tmp) {
	warn "cannot encode Object ID $oid: $BER::errmsg"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }
    return $tmp;
}

1;
