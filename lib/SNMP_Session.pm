package SNMP_Session;

sub AF_INET { 2; }
sub SOCK_STREAM { 2; }
sub SOCK_DGRAM { 1; }

sub open
{
    my($this,$remote_hostname,$community,$port,$max_pdu_len) = @_;
    my($name,$aliases,$local_hostname,$local_addr,$remote_addr);

    $snmp_standard_udp_port = 161;
    $udp_proto = 0;
    $sockaddr = 'S n a4 x8';

    $community = 'public' unless defined $community;
    $port = $snmp_standard_udp_port unless defined $port;
    $max_pdu_len = 8000 unless defined $max_pdu_len;

    (($name,$aliases,$udp_proto) = getprotobyname('ucp'))
	unless $udp_proto;
    chop($local_hostname = `uname -n`);
    $local_addr = (gethostbyname($local_hostname))[4]
	|| die "local host $local_hostname not found: $!";
    $local_addr = pack ($sockaddr, &AF_INET, 0, $local_addr);
    $udp_proto=17 unless $udp_proto;
    $remote_addr = (gethostbyname($remote_hostname))[4]
	|| die "host $remote_hostname not found: $!";
    socket (SOCKET, &AF_INET, &SOCK_DGRAM, $udp_proto)
	|| die "socket: $!";
    bind (SOCKET, $local_addr)
	|| die "bind $local_addr: $!";
    $remote_addr = pack ($sockaddr, &AF_INET, $port, $remote_addr);
    bless {
	'sock' => SOCKET,
	'snmp_version' => 0,
	'community' => $community,
	'remote_addr' => $remote_addr,
	'max_pdu_len' => $max_pdu_len,
	'pdu_buffer' => '\0' x $max_pdu_len,
	'request_id' => rand 0x80000000 + rand 0xffff,
	'timeout' => 3.0
	}, 
    SNMP_Session;
}

sub close
{
    my($this) = shift;
    close ($this->{sock}) || die "close: $!";
}

sub send_query
{
    my($this) = shift;
    my($query) = shift;
    send ($this->{sock},$query,0,$this->{remote_addr});
}

sub wait_for_response
{
    my($this) = shift;
    my($timeout) = shift || 2.0;
    my($rin,$win,$ein) = ('','','');
    my($rout,$wout,$eout);
    vec($rin,fileno($this->{sock}),1) = 1;
    select($rout=$rin,$wout=$win,$eout=$ein,$timeout);
}

sub receive_response
{
    my($this) = shift;
    my($remote_addr);
    ($remote_addr = recv ($this->{sock},$this->{pdu_buffer},$this->{max_pdu_len},0))
	|| return 0;
    if ($remote_addr ne $this->{remote_addr}) {
	warn "Response came from $remote_addr";
	return 0;
    }
    return length $this->{pdu_buffer};
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
	warn "Timeout\n";
    }
}

sub describe
{
    my($this) = shift;
    my($family,$port,@ipaddr) = unpack ('S n C4 x8',$this->{remote_addr});

    printf "SNMP_Session: %d.%d.%d.%d:%d (%d)\n",
    $ipaddr[0],$ipaddr[1],$ipaddr[2],$ipaddr[3],$port,$this->{max_pdu_len};
}

sub encode_get_request
{
    my($this) = shift;
    my(@encoded_oids) = @_;
    grep($_ = BER::encode_sequence($_,BER::encode_null()),@encoded_oids);
    return BER::encode_sequence (BER::encode_int ($this->{snmp_version}),
			       BER::encode_string ($this->{community}),
			       BER::encode_tagged_sequence
				 (0x80,
				BER::encode_int ($this->{request_id}),
				BER::encode_int (0),
				BER::encode_int (0),
				BER::encode_sequence (@encoded_oids)));

}

sub decode_get_response
{
    my($this) = shift;
    my($response) = shift;
    BER::decode_by_template ($response, "%{%0i%*s%162{%*i%0i%0i%{%@", 
			     $this->{community}, $this->{request_id});
}

1;
