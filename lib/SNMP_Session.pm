# -*- mode: Perl -*-
######################################################################
### BER (Basic Encoding Rules) encoding and decoding.
######################################################################
### This module implements encoding and decoding of ASN.1-based data
### structures using the Basic Encoding Rules (BER).  Only the subset
### necessary for SNMP is implemented.
######################################################################
### Created by:  Simon Leinen  <simon@switch.ch>
###
### Contributions and fixes by:
###
### Tobias Oetiker <oetiker@ee.ethz.ch>
### Heine Peters <peters@dkrz.de>
######################################################################

package SNMP_Session;		

use Socket;
use BER;

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
my $default_retries = 3;

### Default backoff factor for SNMP_Session objects.  This factor is
### used to increase the TIMEOUT every time an SNMP request is
### retried.
###
my $default_backoff = 1.5;

sub get_request  { 0 | context_flag };
sub getnext_request  { 1 | context_flag };
sub get_response { 2 | context_flag };

sub standard_udp_port { 161 };

sub open
{
    return SNMPv1_Session::open (@_);
}

sub timeout { $_[0]->{timeout} }
sub retries { $_[0]->{retries} }
sub backoff { $_[0]->{backoff} }

sub encode_request
{
    my($this, $reqtype, @encoded_oids) = @_;
    my($request);

    # turn each of the encoded OIDs into an encoded pair of the OID
    # and a NULL.
    grep($_ = encode_sequence($_,encode_null()),@encoded_oids);

    $request = encode_tagged_sequence
	($reqtype,
	 encode_int ($this->{request_id}),
	 encode_int (0),
	 encode_int (0),
	 encode_sequence (@encoded_oids));
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

sub decode_get_response
{
    my($this, $response) = @_;
    my @rest;
    eval '@rest = $this->unwrap_response ($response, get_response)';
    $@ ? 0 : @rest;
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

sub get_request_response
{
    my($this) = shift;
    my(@oids) = @_;
    return $this->request_response ($this->encode_get_request (@oids));
}

sub getnext_request_response
{
    my($this) = shift;
    my(@oids) = @_;
    return $this->request_response ($this->encode_getnext_request (@oids));
}

sub request_response
{
    my $this = shift;
    my $req = shift;
    my $retries = $this->retries;
    my $timeout = $this->timeout;

    $this->send_query ($req)
	|| die "send_query: $!";
    while ($retries > 0) {
	if ($this->wait_for_response($timeout)) {
	    my($response_length);

	    $response_length = $this->receive_response();
	    return $response_length if $response_length;
	} else {
	    ## No response received - retry
	    --$retries;
	    $timeout *= $this->backoff;
	    $this->send_query ($req)
		|| die "send_query: $!";
	}
    }
    0;
}

package SNMPv1_Session;

use SNMP_Session;
use Socket;
use BER;

@ISA = qw(SNMP_Session);

sub snmp_version { 0 }

sub open
{
    my($this,$remote_hostname,$community,$port,$max_pdu_len) = @_;
    my($name,$aliases,$remote_addr,$socket);

    my $udp_proto = 0;
    my $sockaddr = 'S n a4 x8';

    $community = 'public' unless defined $community;
    $port = SNMP_Session::standard_udp_port unless defined $port;
    $max_pdu_len = 8000 unless defined $max_pdu_len;

    if ($remote_hostname =~ /^\d+\.\d+\.\d+\.\d+$/) {
	$remote_addr = pack('C4',split(/\./,$remote_hostname));
    } else {
	$remote_addr = (gethostbyname($remote_hostname))[4]
	    || die (host_not_found_error ($remote_hostname, $?));
    }
    $socket = 'SNMP'.sprintf ("%08x04x",
			      unpack ("N", $remote_addr), $port);
    (($name,$aliases,$udp_proto) = getprotobyname('udp'))
	unless $udp_proto;
    $udp_proto=17 unless $udp_proto;
    socket ($socket, AF_INET, SOCK_DGRAM, $udp_proto)
	|| die "socket: $!";
    $remote_addr = pack ($sockaddr, AF_INET, $port, $remote_addr);
    bless {
	'sock' => $socket,
	'sockfileno' => fileno ($socket),
	'community' => $community,
	'remote_addr' => $remote_addr,
	'max_pdu_len' => $max_pdu_len,
	'pdu_buffer' => '\0' x $max_pdu_len,
	'request_id' => rand 0x80000000 + rand 0xffff,
	'timeout' => $default_timeout,
	'retries' => $default_retries,
	'backoff' => $default_backoff,
	};
}

sub host_not_found_error
{
    my ($hostname, $h_errno) = @_;
    my ($message);

    $message = "host $hostname not found";
    return $message unless $?;
    return $message.": ".(('no such host', 'temporary name service failure',
			   'name service error', 'host has no address')[$?-1])
	if $? > 0 && $? < 5;
    return $message.", h_errno==".$?;
}

sub sock { $_[0]->{sock} }
sub sockfileno { $_[0]->{sockfileno} }
sub remote_addr { $_[0]->{remote_addr} }
sub pdu_buffer { $_[0]->{pdu_buffer} }
sub max_pdu_len { $_[0]->{max_pdu_len} }

sub close
{
    my($this) = shift;
    close ($this->sock) || die "close: $!";
}

sub wrap_request
{
    my($this) = shift;
    my($request) = shift;

    encode_sequence (encode_int ($this->snmp_version),
		     encode_string ($this->{community}),
		     $request);
}

sub unwrap_response
{
    my($this,$response,$tag) = @_;
    decode_by_template ($response, "%{%0i%*s%*{%*i%0i%0i%{%@", 
			$this->{community}, $tag,
			$this->{request_id});
}

sub send_query
{
    my($this) = shift;
    my($query) = shift;
    send ($this->sock,$query,0,$this->remote_addr);
}

sub receive_response
{
    my($this) = shift;
    my($remote_addr);
    ($remote_addr = recv ($this->sock,$this->{'pdu_buffer'},$this->max_pdu_len,0))
	|| return 0;
    ##
    ## Check whether the response came from the address we've sent the
    ## request to.  If this is not the case, we should probably ignore
    ## it, as it may relate to another request.
    ##
    if ($remote_addr ne $this->{'remote_addr'}) {
	warn "Response came from $remote_addr, not ".$this->remote_addr;
	return 0;
    }
    return length $this->pdu_buffer;
}

sub describe
{
    my($this) = shift;
    my($family,$port,@ipaddr) = unpack ('S n C4 x8',$this->remote_addr);

    printf "SNMP_Session: %d.%d.%d.%d:%d (size %d timeout %g)\n",
    $ipaddr[0],$ipaddr[1],$ipaddr[2],$ipaddr[3],$port,$this->max_pdu_len,
    $this->timeout;
}

1;
