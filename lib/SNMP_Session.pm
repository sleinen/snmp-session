# -*- mode: Perl -*-
######################################################################
### SNMP Request/Response Handling
######################################################################
### The abstract class SNMP_Session defines objects that can be used
### to communicate with SNMP entities.  It has methods to send
### requests to and receive responses from an agent.
###
### Currently it has one subclass, SNMPv1_Session, which implements
### the SNMPv1 protocol.
######################################################################
### Created by:  Simon Leinen  <simon@switch.ch>
###
### Contributions and fixes by:
###
### Matthew Trunnell <matter@media.mit.edu>
### Tobias Oetiker <oetiker@ee.ethz.ch>
### Heine Peters <peters@dkrz.de>
### Daniel L. Needles <dan_needles@INS.COM>
### Mike Mitchell <mcm@unx.sas.com>
######################################################################

package SNMP_Session;		

require 5.002;

use strict qw(vars subs);	# cannot use strict subs here
				# because of the way we use
				# generated file handles
use Exporter;
use vars qw(@ISA $VERSION @EXPORT $errmsg $suppress_warnings);
use Socket;
use BER;

sub map_table ($$$);
sub map_table_start_end ($$$$$);
sub index_compare ($$);
sub oid_diff ($$);

$VERSION = '0.60';

@ISA = qw(Exporter);

@EXPORT = qw(errmsg suppress_warnings index_compare oid_diff);

my $default_debug = 0;

### Default initial timeout (in seconds) waiting for a response PDU
### after a request is sent.  Note that when a request is retried, the
### timeout is increased by BACKOFF (see below).
###
my $default_timeout = 2.0;

### Default number of retries for each SNMP request.  If no response
### is received after TIMEOUT seconds, the request is resent and a new
### response awaited with a longer timeout (see the documentation on
### BACKOFF below).
###
my $default_retries = 5;

### Default backoff factor for SNMP_Session objects.  This factor is
### used to increase the TIMEOUT every time an SNMP request is
### retried.
###
my $default_backoff = 1.0;

$SNMP_Session::errmsg = '';
$SNMP_Session::suppress_warnings = 0;

sub get_request  { 0 | context_flag };
sub getnext_request  { 1 | context_flag };
sub get_response { 2 | context_flag };
sub set_request { 3 | context_flag };
sub trap_request { 4 | context_flag };

sub standard_udp_port { 161 };

sub open
{
    return SNMPv1_Session::open (@_);
}

sub timeout { $_[0]->{timeout} }
sub retries { $_[0]->{retries} }
sub backoff { $_[0]->{backoff} }
sub set_timeout {
    my ($session, $timeout) = @_;
    die "timeout ($timeout) must be a positive number" unless $timeout > 0.0;
    $session->{'timeout'} = $timeout;
}
sub set_retries {
    my ($session, $retries) = @_;
    die "retries ($retries) must be a non-negative integer"
	unless $retries == int ($retries) && $retries >= 0;
    $session->{'retries'} = $retries; 
}
sub set_backoff {
    my ($session, $backoff) = @_;
    die "backoff ($backoff) must be a number >= 1.0"
	unless $backoff == int ($backoff) && $backoff >= 1.0;
    $session->{'backoff'} = $backoff; 
}

sub encode_request ($$@)
{
    my($this, $reqtype, @encoded_oids_or_pairs) = @_;
    my($request);
    local($_);

    ++$this->{request_id};
    foreach $_ (@encoded_oids_or_pairs) {
      if (ref ($_) eq 'ARRAY') {
	$_ = &encode_sequence ($_->[0], $_->[1])
	  || return $this->ber_error ("encoding pair");
      } else {
	$_ = &encode_sequence ($_, encode_null())
	  || return $this->ber_error ("encoding value/null pair");
      }
    }
    $request = encode_tagged_sequence
	($reqtype,
	 encode_int ($this->{request_id}),
	 encode_int_0, encode_int_0,
	 encode_sequence (@encoded_oids_or_pairs))
	  || return $this->ber_error ("encoding request PDU");
    return $this->wrap_request ($request);
}

sub encode_get_request
{
    my($this, @oids) = @_;
    return encode_request ($this, get_request, @oids);
}

sub encode_getnext_request
{
    my($this, @oids) = @_;
    return encode_request ($this, getnext_request, @oids);
}

sub encode_set_request
{
    my($this, @encoded_pairs) = @_;
    return encode_request ($this, set_request, @encoded_pairs);
}

sub encode_trap_request ($$$$$$@)
{
    my($this, $ent, $agent, $gen, $spec, $dt, @pairs) = @_;
    my($request);
    local($_);

    foreach $_ (@pairs) {
      if (ref ($_) eq 'ARRAY') {
	$_ = &encode_sequence ($_->[0], $_->[1])
	  || return $this->ber_error ("encoding pair");
      } else {
	$_ = &encode_sequence ($_, encode_null())
	  || return $this->ber_error ("encoding value/null pair");
      }
    }
    $request = encode_tagged_sequence
	(trap_request, $ent, $agent, $gen, $spec, $dt, encode_sequence (@pairs))
	  || return $this->ber_error ("encoding trap PDU");
    return $this->wrap_request ($request);
}

sub decode_get_response
{
    my($this, $response) = @_;
    my @rest;
    @{$this->{'unwrapped'}};
}

sub decode_trap_request ($$) {
    my ($this, $trap) = @_;
    my ($snmp_version, $community, $ent, $agent, $gen, $spec, $dt, @pairs);
    ($snmp_version, $community, $ent, $agent, $gen, $spec, $dt, @pairs)
	= decode_by_template ($trap, "%{%i%s%*{%O%A%i%i%u%{%@",
			      SNMP_Session::trap_request
			      );
    return undef
	unless $snmp_version == $this->snmp_version ();
    if (!defined $ent) {
	warn "BER error decoding trap:\n  ".$BER::errmsg."\n";
    }
    return ($community, $ent, $agent, $gen, $spec, $dt, @pairs);
}

sub wait_for_response
{
    my($this) = shift;
    my($timeout) = shift || 10.0;
    my($rin,$win,$ein) = ('','','');
    my($rout,$wout,$eout);
    vec($rin,$this->sockfileno,1) = 1;
    select($rout=$rin,$wout=$win,$eout=$ein,$timeout);
}

sub get_request_response ($@)
{
    my($this, @oids) = @_;
    return $this->request_response_5 ($this->encode_get_request (@oids),
				      get_response, \@oids, 1);
}

sub set_request_response ($@)
{
    my($this, @pairs) = @_;
    return $this->request_response_5 ($this->encode_set_request (@pairs),
				      get_response, \@pairs, 1);
}

sub getnext_request_response ($@)
{
    my($this,@oids) = @_;
    return $this->request_response_5 ($this->encode_getnext_request (@oids),
				      get_response, \@oids, 1);
}

sub trap_request_send ($$$$$$@)
{
    my($this, $ent, $agent, $gen, $spec, $dt, @pairs) = @_;
    my($req);

    $req = $this->encode_trap_request ($ent, $agent, $gen, $spec, $dt, @pairs);
    ## Encoding may have returned an error.
    return undef unless defined $req;
    $this->send_query($req)
	|| return $this->error ("send_trap: $!");
    return 1;
}

sub request_response_5 ($$$$$)
{
    my ($this, $req, $response_tag, $oids, $errorp) = @_;
    my $retries = $this->retries;
    my $timeout = $this->timeout;

    ## Encoding may have returned an error.
    return undef unless defined $req;

    $this->send_query ($req)
	|| return $this->error ("send_query: $!");
    while ($retries > 0) {
	if ($this->wait_for_response($timeout)) {
	    my($response_length);

	    $response_length
		= $this->receive_response_3 ($response_tag, $oids, $errorp);
	    if ($response_length) {
		return $response_length;
	    } else {
		return undef;
	    }
	} else {
	    ## No response received - retry
	    --$retries;
	    $timeout *= $this->backoff;
	    $this->send_query ($req)
		|| return $this->error ("send_query: $!");
	}
    }
    $this->error ("no response received");
}


sub error_return ($$)
{
    my ($this,$message) = @_;
    $SNMP_Session::errmsg = $message;
    unless ($SNMP_Session::suppress_warnings) {
	$message =~ s/^/  /mg;
	warn ("Error:\n".$message."\n");
    }
    return undef;
}

sub error ($$)
{
    my ($this,$message) = @_;
    my $session = $this->to_string;
    $SNMP_Session::errmsg = $message."\n".$session;
    unless ($SNMP_Session::suppress_warnings) {
	$session =~ s/^/  /mg;
	$message =~ s/^/  /mg;
	warn ("SNMP Error:\n".$SNMP_Session::errmsg."\n");
    }
    return undef;
}

sub ber_error ($$)
{
  my ($this,$type) = @_;
  my ($errmsg) = $BER::errmsg;

  $errmsg =~ s/^/  /mg;
  return $this->error ("$type:\n$errmsg");
}

sub map_table ($$$) {
  my ($session, $columns, $mapfn) = @_;

  return map_table_start_end ($session, $columns, $mapfn, "", undef);
}

sub map_table_start_end ($$$$$) {
  my ($session, $columns, $mapfn, $start, $end) = @_;

  my @encoded_oids;
  my $call_counter = 0;
  my $base_index = $start;

  do {
    @encoded_oids = @{$columns};
    @encoded_oids = grep ($_=encode_oid (@{$_},split '\.',$base_index),
			  @encoded_oids);
    if ($session->getnext_request_response (@encoded_oids)) {
      my $response = $session->pdu_buffer;
      my ($bindings) = $session->decode_get_response ($response);
      my $smallest_index = undef;
      my @collected_values = ();

      my @bases = @{$columns};
      while ($bindings ne '') {
	my ($binding, $oid, $value);
	my $base = shift @bases;
	($binding, $bindings) = decode_sequence ($bindings);
	($oid, $value) = decode_by_template ($binding, "%O%@");

	my $out_index;

	$out_index = &oid_diff ($base, $oid);
	my $cmp;
	if (!defined $smallest_index
	    || ($cmp = index_compare ($out_index,$smallest_index)) == -1) {
	  $smallest_index = $out_index;
	  grep ($_=undef, @collected_values);
	  push @collected_values, $value;
	} elsif ($cmp == 1) {
	  push @collected_values, undef;
	} else {
	  push @collected_values, $value;
	}
      }
      (++$call_counter,
       &$mapfn ($smallest_index, @collected_values))
	if defined $smallest_index;
      $base_index = $smallest_index;
    } else {
      die "SNMP error";
    }
  }
  while (defined $base_index
	&& (!defined $end || index_compare ($base_index, $end) < 0));
  $call_counter;
}

sub index_compare ($$) {
  my ($i1, $i2) = @_;
  $i1 = '' unless defined $i1;
  $i2 = '' unless defined $i2;
  if ($i1 eq '') {
      return $i2 eq '' ? 0 : 1;
  } elsif ($i2 eq '') {
      return 1;
  } elsif (!$i1) {
      return $i2 eq '' ? 1 : !$i2 ? 0 : 1;
  } elsif (!$i2) {
      return -1;
  } else {
    my ($f1,$r1) = split('\.',$i1,2);
    my ($f2,$r2) = split('\.',$i2,2);

    if ($f1 < $f2) {
      return -1;
    } elsif ($f1 > $f2) {
      return 1;
    } else {
      return index_compare ($r1,$r2);
    }
  }
}

sub oid_diff ($$) {
  my($base, $full) = @_;
  my $base_dotnot = join ('.',@{$base});
  my $full_dotnot = BER::pretty_oid ($full);

  return undef unless substr ($full_dotnot, 0, length $base_dotnot)
    eq $base_dotnot
      && substr ($full_dotnot, length $base_dotnot, 1) eq '.';
  substr ($full_dotnot, length ($base_dotnot)+1);
}

sub version { $VERSION; }

package SNMPv1_Session;

use strict qw(vars subs);	# see above
use vars qw(@ISA);
use SNMP_Session;
use Socket;
use BER;

@ISA = qw(SNMP_Session);

sub snmp_version { 0 }

sub open
{
    my($this,$remote_hostname,$community,$port,$max_pdu_len,$bind_to_port) = @_;
    my($name,$aliases,$remote_addr,$socket);

    my $udp_proto = 0;

    $community = 'public' unless defined $community;
    $port = SNMP_Session::standard_udp_port unless defined $port;
    $max_pdu_len = 8000 unless defined $max_pdu_len;

    ## Changed upon a suggestion by "Daniel L. Needles"
    ## <dan_needles@INS.COM>: on Windows'95, passing numeric IP
    ## addresses to inet_aton() seems to work, but is apparently very
    ## slow.  So if we detect that case, we use a simple conversion.
    ##
    if ($remote_hostname =~ /^\d+\.\d+\.\d+\.\d+(.*)/ )
    {
      $remote_addr = pack("C*",split /\./, $remote_hostname);
    } else {
      $remote_addr = inet_aton ($remote_hostname)
	|| return $this->error_return ("can't resolve \"$remote_hostname\" to IP address");
    }
    $socket = 'SNMP'.sprintf ("%s:%d", inet_ntoa ($remote_addr), $port);
    (($name,$aliases,$udp_proto) = getprotobyname('udp'))
	unless $udp_proto;
    $udp_proto=17 unless $udp_proto;
    socket ($socket, PF_INET, SOCK_DGRAM, $udp_proto)
	|| return $this->error_return ("creating socket: $!");
    if (defined $bind_to_port) {
	my $sockaddr = sockaddr_in ($bind_to_port, INADDR_ANY);
	bind ($socket, $sockaddr)
	    || return $this->error_return ("binding to port %bind_to_port: $!");
    }
    $remote_addr = pack_sockaddr_in ($port, $remote_addr);
    bless {
	   'sock' => $socket,
	   'sockfileno' => fileno ($socket),
	   'community' => $community,
	   'remote_hostname' => $remote_hostname,
	   'remote_addr' => $remote_addr,
	   'max_pdu_len' => $max_pdu_len,
	   'pdu_buffer' => '\0' x $max_pdu_len,
	   'request_id' => int (rand 0x80000000 + rand 0xffff),
	   'timeout' => $default_timeout,
	   'retries' => $default_retries,
	   'backoff' => $default_backoff,
	   'debug' => $default_debug,
	   'error_status' => 0,
	   'error_index' => 0,
	  };
}

sub open_trap_session (@) {
    my ($this, $port) = @_;
    $port = 162 unless defined $port;
    return $this->open ("0.0.0.0", "", 161, undef, $port);
}

sub sock { $_[0]->{sock} }
sub sockfileno { $_[0]->{sockfileno} }
sub remote_addr { $_[0]->{remote_addr} }
sub pdu_buffer { $_[0]->{pdu_buffer} }
sub max_pdu_len { $_[0]->{max_pdu_len} }

sub close
{
    my($this) = shift;
    close ($this->sock) || $this->error ("close: $!");
}

sub wrap_request
{
    my($this) = shift;
    my($request) = shift;

    encode_sequence (encode_int ($this->snmp_version),
		     encode_string ($this->{community}),
		     $request)
      || return $this->ber_error ("wrapping up request PDU");
}

my @error_status_code = qw(noError tooBig noSuchName badValue readOnly
			   genErr noAccess wrongType wrongLength
			   wrongEncoding wrongValue noCreation
			   inconsistentValue resourceUnavailable
			   commitFailed undoFailed authorizationError
			   notWritable inconsistentName);

sub unwrap_response_6
{
    my ($this,$response,$tag,$request_id,$oids,$errorp) = @_;
    my ($community,@rest,$snmpver);

    ($snmpver,$community,$request_id,
     $this->{error_status},
     $this->{error_index},
     @rest)
	= decode_by_template ($response, "%{%i%s%*{%i%i%i%{%@",
			      $tag);
    return $this->ber_error ("Error decoding response PDU")
      unless defined $snmpver;
    return $this->error ("Received SNMP response with unknown snmp-version field $snmpver")
	unless $snmpver == $this->snmp_version;
    if ($this->{error_status} != 0 || $this->{error_index} != 0) {
      if ($errorp) {
	my ($oid, $errmsg);
	$errmsg = $error_status_code[$this->{error_status}] || $this->{error_status};
	$oid = $oids->[$this->{error_index}-1]
	  if $this->{error_index} > 0 && $this->{error_index}-1 <= $#{$oids};
	$oid = $oid->[0]
	  if ref($oid) eq 'ARRAY';
	return $this->error ("Received SNMP response with error code\n"
			     ."  error status: $errmsg\n"
			     ."  index ".$this->{error_index}
			     .(defined $oid
			       ? " (OID: ".&BER::pretty_oid($oid).")"
			       : ""));
      } else {
	if ($this->{error_index} == 1) {
	  @rest[$this->{error_index}-1..$this->{error_index}] = ();
	}
      }
    }
    if ($this->{'debug'}) {
	warn "$community != $this->{community}"
	    unless $SNMP_Session::suppress_warnings
	      || $community eq $this->{community};
	warn "$request_id != $this->{request_id}"
	    unless $SNMP_Session::suppress_warnings
	      || $request_id == $this->{request_id};
    }
    return undef unless $community eq $this->{community};
    return undef unless $request_id == $this->{request_id};
    @rest;
}

sub send_query ($$)
{
    my ($this,$query) = @_;
    send ($this->sock,$query,0,$this->remote_addr);
}

sub receive_response_3
{
    my ($this, $response_tag, $oids, $errorp) = @_;
    my ($remote_addr);
    $remote_addr = recv ($this->sock,$this->{'pdu_buffer'},$this->max_pdu_len,0);
    return 0 unless $remote_addr;
    my $response = $this->{'pdu_buffer'};
    ##
    ## Check whether the response came from the address we've sent the
    ## request to.  If this is not the case, we should probably ignore
    ## it, as it may relate to another request.
    ##
    if ($this->{'debug'} && $remote_addr ne $this->{'remote_addr'}) {
	warn "Response came from ".&pretty_address ($remote_addr)
	    .", not ".&pretty_address($this->{'remote_addr'})
		unless $SNMP_Session::suppress_warnings;
    }

    my @unwrapped = ();
    @unwrapped = $this->unwrap_response_6 ($response, $response_tag, $this->{"request_id"}, $oids, $errorp);
    if (!defined $unwrapped[0]) {
	$this->{'unwrapped'} = undef;
	return 0;
    }
    $this->{'unwrapped'} = \@unwrapped;
    return length $this->pdu_buffer;
}

sub receive_trap
{
    my ($this) = @_;
    my ($remote_addr, $iaddr, $port, $trap);
    $remote_addr = recv ($this->sock,$this->{'pdu_buffer'},$this->max_pdu_len,0);
    return undef unless $remote_addr;
    ($port, $iaddr) = sockaddr_in($remote_addr);
    $trap = $this->{'pdu_buffer'};
    return ($trap, $iaddr, $port);
}

sub pretty_address
{
    my($addr) = shift;
    my($port,$ipaddr) = unpack_sockaddr_in($addr);
    return sprintf ("[%s].%d",inet_ntoa($ipaddr),$port);
}

sub describe
{
    my($this) = shift;
    print $this->to_string (),"\n";
}

sub to_string
{
    my($this) = shift;
    my ($class,$prefix);

    $class = ref($this);
    $prefix = ' ' x (length ($class) + 2);
    ($class." (remote host: \"".$this->{remote_hostname}
     ."\" ".&pretty_address ($this->remote_addr)."\n"
     .$prefix."  community: \"".$this->{'community'}."\"\n"
     .$prefix." request ID: ".$this->{'request_id'}."\n"
     .$prefix."PDU bufsize: ".$this->{'max_pdu_len'}." bytes\n"
     .$prefix."    timeout: ".$this->{timeout}."s\n"
     .$prefix."    retries: ".$this->{retries}."\n"
     .$prefix."    backoff: ".$this->{backoff}.")");
##    sprintf ("SNMP_Session: %s (size %d timeout %g)",
##	       &pretty_address ($this->remote_addr),$this->max_pdu_len,
##	       $this->timeout);
}

1;
