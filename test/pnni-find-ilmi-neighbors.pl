#!/usr/local/bin/perl -w

use strict;

use BER;
use SNMP_Session "0.57";

sub usage();

my $host = shift @ARGV || usage();
my $community = shift @ARGV || 'public';

my $pnniRouteAddrProto = [1,3,6,1,4,1,353,5,4,1,1,19,4,1,8];

my $session = SNMP_Session->open ($host, $community, 161)
    || die "couldn't open SNMP session";
$session->map_table ([$pnniRouteAddrProto],
  sub { 
      my ($index, $proto) = @_;
      grep (defined $_ && ($_=pretty_print $_),
	    ($proto));
      ## we are only interested in routes whose proto is local(2).
      return unless $proto == 2;
      my @index = split ('\.',$index);
      my $nsap = join (".", grep ($_=sprintf ("%02x",$_),@index[1..19])); 
      my $prefix_length = $index[20];
      print $nsap,"/",$prefix_length,"\n";
  });
$session->close;
1;

sub usage () {
    die "Usage: $0 host [community]";
}
