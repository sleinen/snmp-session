#!/usr/bin/perl -w

use strict;

use BER;
use SNMP_Session;
use SNMP_util "0.86";

sub usage () {
    die "Usage: $0 community\@host\n";
}

my $host = shift @ARGV || usage ();

sub out_interface {
  my ($index, $descr, $in, $out, $comment) = @_;

  printf "%2d  %-24s %10s %10s %s\n",
  $index,
  defined $descr ? $descr : '',
  defined $in ? $in/1000.0 : '-',
  defined $out ? $out/1000.0 : '-',
  defined $comment ? $comment : '';
}

snmpmap_table ($host,
	       \&out_interface,
	       qw(ifDescr locIfInBitsSec locIfOutBitsSec locIfDescr));
1;
