#!/usr/bin/perl

#"\x04\x06\x70\x75\x62\x6C\x69\x63" eq BER::encode_string ('public') || die;
#"\x02\x04\x4A\xEC\x31\x16" eq BER::encode_int (0x4aec3116) || die;

srand();

$session = SNMP_Session->open ('liasg5', 'public', 161);
$session->get_request_response (BER::encode_oid (1, 3, 6, 1, 2, 1, 1, 1, 0));
$session->close();

require 5;

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
	'socket' => SOCKET,
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
    close ($this->{socket}) || die "close: $!";
}

sub send_query
{
    my($this) = shift;
    my($query) = shift;
    send ($this->{socket},$query,0,$this->{remote_addr});
}

sub wait_for_response
{
    my($this) = shift;
    my($timeout) = shift || 2.0;
    my($rin,$win,$ein) = ('','','');
    my($rout,$wout,$eout);
    vec($rin,fileno($this->{socket}),1) = 1;
    select($rout=$rin,$wout=$win,$eout=$ein,$timeout);
}

sub receive_response
{
    my($this) = shift;
    my($remote_addr);
    ($remote_addr = recv ($this->{socket},$this->{pdu_buffer},$this->{max_pdu_len},0))
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
	print STDERR "$response_length bytes of response received.\n";
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
    return BER::encode_sequence (BER::encode_int (0),
			       BER::encode_string ($this->{community}),
			       BER::encode_tagged_sequence
				 (0x80,
				BER::encode_int ($this->{request_id}),
				BER::encode_int (0),
				BER::encode_int (0),
				BER::encode_sequence (@encoded_oids)));

}

package BER;

sub encode_header
{
    my($type,$length) = @_;
    return pack ("C C", $type, $length) if $length < 128;
    return pack ("C C C", $type, 1, $length) if $length < 256;
    return pack ("C C n", $type, 2, $length) if $length < 65536;
    die "Cannot encode length $length yet";
}

sub encode_int
{
    my($int)=@_;
    return &encode_header (2, 1).pack ("C", $int)
	if $int >= -128 && $int < 128;
    return &encode_header (2, 2).pack ("n", $int)
	if $int >= -32768 && $int < 32768;
    return &encode_header (2, 4).pack ("N", $int);
    die "Cannot encode integer $int yet";
}

sub encode_oid
{
    my(@oid)=@_;
    my($result,$subid);

    $result = '';
    if ($#oid > 1) {
	$result = pack ("C", $oid[0]*40+$oid[1]);
	shift @oid;
	shift @oid;
    }
    foreach $subid (@oid) {
	if ($subid < 128) {
	    $result .= pack ("C", $subid);
	} else {
	    die "Cannot encode subid $subid";
	}
    }
    return pack ("C C", 6, length $result).$result;
}

sub encode_null
{
    return &encode_header (5, 0);
}

sub encode_sequence
{
    my($result);

    $result = join '',@_;
    return encode_header (0x30, length $result).$result;
}

sub encode_tagged_sequence
{
    my($tag,$result);

    $tag = shift @_;
    $result = join '',@_;
    return encode_header (0x20 | $tag, length $result).$result;
}

sub encode_string
{
    my($string)=@_;
    return encode_header (4, length $string).$string;
}
