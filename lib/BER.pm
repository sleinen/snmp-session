package BER;

sub encode_header
{
    my($type,$length) = @_;
    return pack ("C C", $type, $length) if $length < 128;
    return pack ("C C C", $type, 0x80 | 1, $length) if $length < 256;
    return pack ("C C n", $type, 0x80 | 2, $length) if $length < 65536;
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

sub pretty_print
{
    my($packet) = shift;
    my($type,$rest);
    $result = ord (substr ($packet, 0, 1));
    return &pretty_int ($packet) if $result == 2;
    return &pretty_string ($packet) if $result == 4;
    return &pretty_oid ($packet) if $result == 6;
    die "Cannot pretty print objects of type $type";
}

sub pretty_string
{
    my($packet) = shift;
    my($decoded,$rest);
    ($decoded,$rest) = &decode_string ($packet);
    die "Junk after object" unless $rest eq '';
    return $decoded;
}

sub pretty_int
{
    my($packet) = shift;
    my($decoded,$rest);
    ($decoded,$rest) = &decode_int ($packet);
    die "Junk after object" unless $rest eq '';
    return $decoded;
}

sub pretty_oid
{
    my($oid) = shift;
    my($result,$subid);
    my(@result,@oid);
    $result = ord (substr ($oid, 0, 1));
    die "Object ID expected" unless $result == 6;
    ($result, $oid) = &decode_length (substr ($oid, 1));
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
    die "Object ID expected" unless $result == 6;
    ($result, $pdu_rest) = &decode_length (substr ($pdu, 1));
    @result = (substr ($pdu, 0, $result + (length ($pdu) - length ($pdu_rest))),
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
		$expected = shift if ($expected eq '*');
		$expected = 0x30 if $expected eq '';
		die "Expected sequence tag $expected, got ", ord (substr ($pdu, 0, 1))
		    unless (ord (substr ($pdu, 0, 1)) == $expected);
		$pdu = substr ($pdu,1);
		(($length,$pdu) = decode_length ($pdu)) || die "cannot read length";
		die "Expected length $length" unless length $pdu == $length;
		@results = decode_by_template ($pdu, $_, @_);
		$pdu = ''; $_ = '';
		last;
	    } elsif (/^\*s(.*)/) {
		$_ = $1;
		$expected = shift @_;
		(($read,$pdu) = &decode_string ($pdu)) || die "cannot read string";
		die "Expected $expected, read $read" unless $expected eq $read;
	    } elsif (/^O(.*)/) {
		$_ = $1;
		(($read,$pdu) = &decode_oid ($pdu)) || die "cannot read OID";
		push @results, $read;
	    } elsif (($expected) = /^(\d*|\*)i(.*)/) {
		$_ = $2;
		$expected = shift if $expected eq '*';
		(($read,$pdu) = &decode_int ($pdu)) || die "cannot read int";
		warn (sprintf ("Expected %d (0x%x), got %d (0x%x)",
			       $expected, $expected, $read, $read))
		    unless ($expected == $read);
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
    die "Sequence expected" unless $result == 0x30;
    ($result, $pdu) = &decode_length (substr ($pdu, 1));
    @result = (substr ($pdu, 0, $result), substr ($pdu, $result));
    @result;
}

sub decode_int
{
    my($pdu) = shift;
    my($result);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    die "Integer expected" unless $result == 2;
    $result = ord (substr ($pdu, 1, 1));
    if ($result == 1) {
	@result = (ord (substr ($pdu, 2, 1)), substr ($pdu, 3));
    } elsif ($result == 2) {
	@result = (unpack ("n", (substr ($pdu, 2))), substr ($pdu, 4));
    } elsif ($result == 4) {
	@result = (unpack ("N", (substr ($pdu, 2))), substr ($pdu, 6));
    } else {
	die "Unsupported integer length $length";
    }
    @result;
}

sub decode_string
{
    my($pdu) = shift;
    my($result,$length);
    my(@result);
    $result = ord (substr ($pdu, 0, 1));
    die "Expected type 4" unless $result == 4;
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
    if ($result & 0x80) {
	if ($result == 0x81) {
	    @result = (ord (substr ($pdu, 1, 1)), substr ($pdu, 2));
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
