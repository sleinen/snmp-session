#!/usr/local/bin/perl

######################################################################
### Name:	  ber-test.pl
### Date Created: Sat Feb  1 16:09:46 1997
### Author:	  Simon Leinen  <simon@switch.ch>
### RCS $Id: ber-test.pl,v 1.1 1997-02-01 15:46:57 simon Exp $
######################################################################

use BER;

my $exitcode = 0;
&regression_test;
exit ($exitcode);

#### Regression Tests

sub regression_test
{
    &eq_test ('encode_string ("public")', "\x04\x06\x70\x75\x62\x6C\x69\x63");
    &eq_test ('encode_int (0x4aec3116)', "\x02\x04\x4A\xEC\x31\x16");
    &equal_test ('(&BER::decode_intlike ("\x02\x01\x01"))[0]', 1);
    &equal_test ('(&BER::decode_intlike ("\x02\x02\x01\x01"))[0]', 257);
    &equal_test ('(&BER::decode_intlike ("\x02\x02\xff\xff"))[0]', -1);
    &equal_test ('(&BER::decode_unsignedlike ("\x02\x02\xff\xff"))[0]', 65535);
    &equal_test ('(&BER::decode_intlike ("\x02\x03\xff\xff\xff"))[0]', -1);
    &equal_test ('(&BER::decode_unsignedlike ("\x02\x03\xff\xff\xff"))[0]', 16777215);
    &equal_test ('(&BER::decode_intlike ("\x02\x04\xff\xff\xff\xff"))[0]', -1);
    &equal_test ('(&BER::decode_unsignedlike ("\x02\x04\xff\xff\xff\xff"))[0]', 4294967295);
    &equal_test ('(&BER::decode_intlike ("\x02\x05\x00\xff\xff\xff\xff"))[0]', 4294967295);
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
