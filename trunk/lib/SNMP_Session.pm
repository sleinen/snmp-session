package SNMP_Session;		# -*- mode: Perl -*-

use Socket;
use BER;

sub get_request  { 0 | context_flag };
sub get_response { 2 | context_flag };

sub standard_udp_port { 161 };

sub open
{
    return SNMPv1_Session::open (@_);
}

sub encode_get_request
{
    my($this, @encoded_oids) = @_;
    my($request);

    # turn each of the encoded OIDs into an encoded pair of the OID
    # and a NULL.
    grep($_ = encode_sequence($_,encode_null()),@encoded_oids);

    $request = encode_tagged_sequence
	(get_request,
	 encode_int ($this->{request_id}),
	 encode_int (0),
	 encode_int (0),
	 encode_sequence (@encoded_oids));
    return $this->wrap_request ($request);
}

sub decode_get_response
{
    my($this, $response) = @_;
    $this->unwrap_response ($response, get_response);
}

sub wait_for_response
{
    my($this) = shift;
    my($timeout) = shift || 2.0;
    my($rin,$win,$ein) = ('','','');
    my($rout,$wout,$eout);
    vec($rin,$this->sockfileno,1) = 1;
    select($rout=$rin,$wout=$win,$eout=$ein,$timeout);
}

sub get_request_response
{
    my($this) = shift;
    my(@oids) = @_;
    $this->send_query ($this->encode_get_request (@oids))
	|| die "send_query: $!";
    if ($this->wait_for_response($this->{timeout})) {
	my($response_length);

	($response_length = $this->receive_response())
	    || die "receive_response: $!";
	## print STDERR "$response_length bytes of response received.\n";
    } else {
	0;
    }
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
    my($name,$aliases,$local_hostname,$local_addr,$remote_addr,$socket);

    $udp_proto = 0;
    $sockaddr = 'S n a4 x8';

    $community = 'public' unless defined $community;
    $port = SNMP_Session::standard_udp_port unless defined $port;
    $max_pdu_len = 8000 unless defined $max_pdu_len;

    $remote_addr = (gethostbyname($remote_hostname))[4]
	|| die (host_not_found_error ($remote_hostname, $?));
    $socket = 'SNMP'.sprintf ("%08x04x",
			      unpack ("N", $remote_addr), $port);
    (($name,$aliases,$udp_proto) = getprotobyname('udp'))
	unless $udp_proto;
    $udp_proto=17 unless $udp_proto;
    chop($local_hostname = `uname -n`);
    $local_addr = (gethostbyname($local_hostname))[4]
	|| die (host_not_found_error ($local_hostname, $?));
    $local_addr = pack ($sockaddr, AF_INET, 0, $local_addr);
    socket ($socket, AF_INET, SOCK_DGRAM, $udp_proto)
	|| die "socket: $!";
    bind ($socket, $local_addr)
	|| die "bind $local_addr: $!";
    $remote_addr = pack ($sockaddr, AF_INET, $port, $remote_addr);
    bless {
	'sock' => $socket,
	'sockfileno' => fileno ($socket),
	'community' => $community,
	'remote_addr' => $remote_addr,
	'max_pdu_len' => $max_pdu_len,
	'pdu_buffer' => '\0' x $max_pdu_len,
	'request_id' => rand 0x80000000 + rand 0xffff,
	'timeout' => 3.0
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

sub sock { @_[0]->{sock} }
sub sockfileno { @_[0]->{sockfileno} }
sub remote_addr { @_[0]->{remote_addr} }
sub pdu_buffer { @_[0]->{pdu_buffer} }
sub max_pdu_len { @_[0]->{max_pdu_len} }
sub timeout { @_[0]->{timeout} }

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
    ($remote_addr = recv ($this->sock,$this->{pdu_buffer},$this->max_pdu_len,0))
	|| return 0;
    if ($remote_addr ne $this->remote_addr) {
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
    $this->{timeout};
}

1;
