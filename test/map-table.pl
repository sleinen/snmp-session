#!/usr/local/bin/perl -w

require 5.003;

use strict;

use BER;
use SNMP_Session;

&SNMP_Session::ic_test;

my $host = shift @ARGV || die;
my $community = shift @ARGV || die;

my $ifDescr = [1,3,6,1,2,1,2,2,1,2];
my $ifInOctets = [1,3,6,1,2,1,2,2,1,10];
my $ifOutOctets = [1,3,6,1,2,1,2,2,1,16];
my $locIfInBitsSec = [1,3,6,1,4,1,9,2,2,1,1,6];
my $locIfOutBitsSec = [1,3,6,1,4,1,9,2,2,1,1,8];
my $locIfDescr = [1,3,6,1,4,1,9,2,2,1,1,28];

sub out_interface {
  my ($index, $descr, $in, $out, $comment) = @_;
  printf "%2d  %-20s %10s %10s %s\n",
  $index,
  defined $descr ? $descr : '',
  defined $in ? $in/1000.0 : '-',
  defined $out ? $out/1000.0 : '-',
  defined $comment ? $comment : '';
}

my $session = SNMP_Session->open ($host, $community, 161)
  || die "Opening SNMP_Session";
$session->map_table ([$ifDescr,$locIfInBitsSec,$locIfOutBitsSec,$locIfDescr],
		     \&out_interface);
1;

package SNMP_Session;

sub map_table ($$$) {
  my ($session, $columns, $mapfn) = @_;

  my @encoded_oids;
  my $index = "";

  do {
    @encoded_oids = @{$columns};
    @encoded_oids = grep ($_=encode_oid (@{$_},split '\.',$index),
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
	my $cmp = index_compare ($out_index,$smallest_index);
	if ($cmp == -1) {
	  $smallest_index = $out_index;
	  grep ($_=undef, @collected_values);
	  push @collected_values, pretty_print ($value);
	} elsif ($cmp == 1) {
	  push @collected_values, undef;
	} else {
	  push @collected_values, pretty_print ($value);
	}
      }
      &$mapfn ($smallest_index, @collected_values)
	if $smallest_index;
      $index = $smallest_index;
    } else {
      die "SNMP error";
    }
  }
  while ($index);
}

sub ic_test () {
  die "1" unless index_compare ("1.2.3","1.2.4") == -1;
  die "2" unless index_compare ("1.2.3","1.2.3") == 0;
  die "3" unless index_compare ("1.2.4","1.2.3") == 1;
}

sub index_compare ($$) {
  my ($i1, $i2) = @_;
  if (!$i1) {
    return !$i2 ? 0 : 1;
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
