#!/usr/local/bin/perl -w
######################################################################
### Name:	  ber-test.pl
### Date Created: Sat Feb  1 16:09:46 1997
### Author:	  Simon Leinen  <simon@switch.ch>
### RCS $Id: ber-test.pl,v 1.2 1997-02-01 16:07:42 simon Exp $
######################################################################
### Regression Tests for BER encoding/decoding
######################################################################

use BER;

use integer;

my $exitcode = 0;
&regression_test;
exit ($exitcode);

#### Regression Tests

sub regression_test
{
    &eq_test ('encode_string ("public")', "\x04\x06\x70\x75\x62\x6C\x69\x63");
    &eq_test ('encode_int (0x4aec3116)', "\x02\x04\x4A\xEC\x31\x16");
    &equal_test ('(&BER::decode_intlike ("\x02\x01\x01"))[0]', 1);
    &equal_test ('(&BER::decode_intlike ("\x02\x01\xff"))[0]', -1);
    &equal_test ('(&BER::decode_intlike ("\x02\x02\x01\x02"))[0]', 258);
    &equal_test ('(&BER::decode_intlike ("\x02\x02\xff\xff"))[0]', -1);
    &equal_test ('(&BER::decode_intlike ("\x02\x03\x00\xff\xfe"))[0]', 65534);
    &equal_test ('(&BER::decode_intlike ("\x02\x03\xff\xff\xfd"))[0]', -3);
    &equal_test ('(&BER::decode_intlike ("\x02\x04\x00\xff\xff\xfd"))[0]', 16777213);
    &equal_test ('(&BER::decode_intlike ("\x02\x04\xff\xff\xff\xfc"))[0]', -4);
    &equal_test ('(&BER::decode_intlike ("\x02\x05\x00\xff\xff\xff\xfc"))[0]', 4294967292);
    &eq_test ('(&BER::decode_string ("\x04\x06public"))[0]', "public");
}

sub eq_test
{
    my ($expr, $wanted) = @_;
    local ($result);
    undef $@;
    eval "\$result = $expr";
    die "$@" if $@;
    (warn "$expr => $result != $wanted"), ++$exitcode
	unless $result eq $wanted;
}

sub equal_test
{
    my ($expr, $wanted) = @_;
    local ($result);
    undef $@;
    eval "\$result = $expr";
    die "$@" if $@;
    (warn "$expr => $result != $wanted"), ++$exitcode
	unless $result == $wanted;
}
