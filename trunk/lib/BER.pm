package BER;			# -*- mode: Perl -*-

use Exporter;

@ISA = qw(Exporter);

@EXPORT = qw(context_flag constructor_flag
	     encode_sequence encode_tagged_sequence encode_string
	     encode_int encode_null encode_oid
	     decode_sequence decode_by_template
	     pretty_print);

sub universal_flag	{ 0x00 }
sub application_flag	{ 0x40 }
sub context_flag	{ 0x80 }
sub private_flag	{ 0xc0 }

sub primitive_flag	{ 0x00 }
sub constructor_flag	{ 0x20 }

sub boolean_tag		{ 0x01 }
sub int_tag		{ 0x02 }
sub bit_string_tag	{ 0x03 }
sub octet_string_tag	{ 0x04 }
sub null_tag		{ 0x05 }
sub object_id_tag	{ 0x06 }
sub sequence_tag	{ 0x10 }
sub set_tag		{ 0x11 }

sub long_length		{ 0x80 }

## SNMP specific tags

sub snmp_ip_address_tag		{ 0x00 | application_flag }
sub snmp_counter32_tag		{ 0x01 | application_flag }
sub snmp_gauge32_tag		{ 0x02 | application_flag }
sub snmp_timeticks_tag		{ 0x03 | application_flag }
sub snmp_opaque_tag		{ 0x04 | application_flag }
sub snmp_nsap_address_tag	{ 0x05 | application_flag }
sub snmp_counter64_tag		{ 0x06 | application_flag }
sub snmp_uinteger32_tag		{ 0x07 | application_flag }
				
sub encode_header
{
    my($type,$length) = @_;
    return pack ("C C", $type, $length) if $length < 128;
    return pack ("C C C", $type, long_length | 1, $length) if $length < 256;
    return pack ("C C n", $type, long_length | 2, $length) if $length < 65536;
    die "Cannot encode length $length yet";
}

sub encode_int
{
    my($int)=@_;
    return ($int >= -128 && $int < 128)
	? encode_header (2, 1).pack ("C", $int)
	    : ($int >= -32768 && $int < 32768)
		? encode_header (2, 2).pack ("n", $int)
		    : encode_header (2, 4).pack ("N", $int);
}

sub encode_oid
{
    my(@oid)=@_;
    my($result,$subid);

    $result = '';
    if ($#oid > 1) {
	$result = shift @oid;
	$result *= 40;
	$result += shift @oid;
	$result = pack ("C", $result);
    }
    foreach $subid (@oid) {
	if ($subid < 128) {
	    $result .= pack ("C", $subid);
	} else {
	    die "Cannot encode subid $subid";
	}
    }
    encode_header (object_id_tag, length $result).$result;
}

sub encode_null
{
    encode_header (null_tag, 0);
}

sub encode_sequence
{
    encode_tagged_sequence (sequence_tag, @_);
}

sub encode_tagged_sequence
{
    my($tag,$result);

    $tag = shift @_;
    $result = join '',@_;
    return encode_header ($tag | constructor_flag, length $result).$result;
}

sub encode_string
{
    my($string)=@_;
    return encode_header (octet_string_tag, length $string).$string;
}

sub pretty_print
{
    my($packet) = shift;
    my($type,$rest);
    $result = ord (substr ($packet, 0, 1));
    return pretty_intlike ($packet)
	if $result == int_tag
	    || $result == snmp_counter32_tag
		|| $result == snmp_gauge32_tag;
    return pretty_string ($packet) if $result == octet_string_tag;
    return pretty_oid ($packet) if $result == object_id_tag;
    return "(null)" if $result == null_tag;
    die "Cannot pretty print objects of type $result";
}

sub pretty_using_decoder
{
    my($decoder) = shift;
    my($packet) = shift;
    my($decoded,$rest);
    ($decoded,$rest) = &$decoder ($packet);
    die "Junk after object" unless $rest eq '';
    return $decoded;
}

sub pretty_string
{
    pretty_using_decoder (\&decode_string, @_);
}

sub pretty_intlike
{
    pretty_using_decoder (\&decode_intlike, @_);
}

sub pretty_oid
{
    my($oid) = shift;
    my($result,$subid);
    my(@result,@oid);
    $result = ord (substr ($oid, 0, 1));
    die "Object ID expected" unless $result == object_id_tag;
    ($result, $oid) = decode_length (substr ($oid, 1));
    die unless $result == length $oid;
    @oid = ();
    $subid = ord (substr ($oid, 0, 1));
    push @oid, int ($subid / 40);
    push @oid, $subid % 40;
    $oid = substr ($oid, 1);
    while ($oid ne '') {
	$subid = ord (substr ($oid, 0, 1));
	$oid = substr ($oid, 1);
	die unless $subid < 128;
	push @oid, $subid;
    }
    $pdu = substr ($pdu, $result);
    join ('.', @oid);
}

sub decode_oid
{
    my($pdu) = shift;
    my($result,$pdu_rest);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    die "Object ID expected" unless $result == object_id_tag;
    ($result, $pdu_rest) = decode_length (substr ($pdu, 1));
    @result = (substr ($pdu, 0, $result + (length($pdu) - length($pdu_rest))),
	       substr ($pdu_rest, $result));
    @result;
}

sub decode_by_template
{
    my($pdu) = shift;
    local($_) = shift;
    my(@results);
    my($length,$expected,$read);
    while (length > 0) {
	if (substr ($_, 0, 1) eq '%') {
	    ## print STDERR "template $_ ", length $pdu," bytes remaining\n";
	    $_ = substr ($_,1);
	    if (($expected) = /^(\d*|\*)\{(.*)/) {
		$_ = $2;
		$expected = shift | constructor_flag if ($expected eq '*');
		$expected = sequence_tag | constructor_flag
		    if $expected eq '';
		die "Expected sequence tag $expected, got ",
		ord (substr ($pdu, 0, 1))
		    unless (ord (substr ($pdu, 0, 1)) == $expected);
		$pdu = substr ($pdu,1);
		(($length,$pdu) = decode_length ($pdu))
		    || die "cannot read length";
		die "Expected length $length, got ".length $pdu unless length $pdu == $length;
	    } elsif (/^\*s(.*)/) {
		$_ = $1;
		$expected = shift @_;
		(($read,$pdu) = decode_string ($pdu))
		    || die "cannot read string";
		die "Expected $expected, read $read"
		    unless $expected eq $read;
	    } elsif (/^O(.*)/) {
		$_ = $1;
		(($read,$pdu) = decode_oid ($pdu)) || die "cannot read OID";
		push @results, $read;
	    } elsif (($expected) = /^(\d*|\*)i(.*)/) {
		$_ = $2;
		$expected = int (shift) if $expected eq '*';
		(($read,$pdu) = decode_int ($pdu)) || die "cannot read int";
		warn (sprintf ("Expected %d (0x%x), got %d (0x%x)",
			       $expected, $expected, $read, $read))
		    unless $expected == $read;
	    } elsif (/^\@(.*)/) {
		$_ = $1;
		push @results, $pdu;
		$pdu = '';
	    } else {
		die "Unknown decoding directive in template: $_";
	    }
	} else {
	    if (substr ($_, 0, 1) ne substr ($pdu, 0, 1)) {
		die "Expected ",substr ($_, 0, 1),", got ",substr ($pdu, 0, 1);
	    }
	    $_ = substr ($_,1);
	    $pdu = substr ($pdu,1);
	}
    }
    die "PDU too long" if (length $pdu > 0);
    die "PDU too short" if (length > 0);
    @results;
}

sub decode_sequence
{
    my($pdu) = shift;
    my($result);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    die "Sequence expected" unless $result == sequence_tag | constructor_flag;
    ($result, $pdu) = decode_length (substr ($pdu, 1));
    @result = (substr ($pdu, 0, $result), substr ($pdu, $result));
    @result;
}

sub decode_int
{
    my($pdu) = shift;
    die "Integer expected" unless ord (substr ($pdu, 0, 1)) == int_tag;
    decode_intlike ($pdu);
}

sub decode_intlike
{
    my($pdu) = shift;
    my($result);
    my(@result);
    $result = ord (substr ($pdu, 1, 1));
    if ($result == 1) {
	@result = (ord (substr ($pdu, 2, 1)), substr ($pdu, 3));
    } elsif ($result == 2) {
	@result = (unpack ("n", (substr ($pdu, 2, 2))), substr ($pdu, 4));
    } elsif ($result == 3) {
	@result = ((ord (substr ($pdu, 2, 1)) << 16) 
		   + unpack ("n", (substr ($pdu, 3, 2))), substr ($pdu, 5));
    } elsif ($result == 4) {
	@result = (unpack ("N", (substr ($pdu, 2, 4))), substr ($pdu, 6));
    } else {
	die "Unsupported integer length $result";
    }
    @result;
}

sub decode_string
{
    my($pdu) = shift;
    my($result,$length);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    die "Expected octet string" unless $result == octet_string_tag;
    $length = ord (substr ($pdu, 1, 1));
    die "Unsupported length" unless $length < 128;
    @result = (substr ($pdu, 2, $length), substr ($pdu, 2+$length));
    @result;
}

sub decode_length
{
    my($pdu) = shift;
    my($result);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    if ($result & long_length) {
	if ($result == (long_length | 1)) {
	    @result = (ord (substr ($pdu, 1, 1)), substr ($pdu, 2));
	} elsif ($result == (long_length | 2)) {
	    @result = ((ord (substr ($pdu, 1, 1)) << 8)
		       + ord (substr ($pdu, 2, 1)), substr ($pdu, 3));
	} else {
	    die "Unsupported length";
	}
    } else {
	@result = ($result, substr ($pdu, 1));
    }
    @result;
}

sub regression_test
{
    "\x04\x06\x70\x75\x62\x6C\x69\x63" eq encode_string ('public') || die;
    "\x02\x04\x4A\xEC\x31\x16" eq encode_int (0x4aec3116) || die;
}

1;
