#!/usr/local/bin/perl -w
###
### Use map_table to list the ipAddrTable.

use strict;
use BER;
use SNMP_Session;

my $hostname = $ARGV[0] || die "usage: $0 target [community]";
my $community = $ARGV[1] || 'public';

my $ifDescr		= [1,3,6,1,2,1,2,2,1,2];
my $ipAdEntAddr		= [1,3,6,1,2,1,4,20,1,1];
my $ipAdEntIfIndex	= [1,3,6,1,2,1,4,20,1,2];
my $ipAdEntNetmask	= [1,3,6,1,2,1,4,20,1,3];
my $ipAdEntBcastAddr	= [1,3,6,1,2,1,4,20,1,4];
my $ipAdEntReasmMaxSize = [1,3,6,1,2,1,4,20,1,5];

my $session;

### If this is zero, the function pretty_net_and_mask will always
### print the prefix length in classless notation
### (e.g. 130.59.0.0/16), even if the prefix length is the classful
### default one for the address range in question.
###
my $use_classful_defaults = 0;

die "Couldn't open SNMP session to $hostname"
    unless ($session = SNMP_Session->open ($hostname, $community, 161));

my $if_descr = get_if_descrs ($session);

printf "%-18s %s\n", "IP address", "if#";
$session->map_table ([$ipAdEntAddr, $ipAdEntIfIndex,
		      $ipAdEntNetmask, $ipAdEntBcastAddr,
		      $ipAdEntReasmMaxSize],
		     sub {
			 my ($index, $addr, $if_index, $netmask,
			     $bcast, $reasm) = @_;
			 grep (defined $_ && ($_=pretty_print $_),
			       ($addr, $if_index, $netmask,
				$bcast, $reasm));
			 printf "%-18s %-20s %d %6d\n",
				 pretty_net_and_mask ($addr, $netmask),
				 $if_descr->{$if_index},
				 $bcast, $reasm;
		     });
$session->close ();

1;

sub netmask_to_prefix_length ($) {
    my ($mask) = @_;
    $mask = pack ("CCCC", split (/\./, $mask));
    $mask = unpack ("N", $mask);
    my ($k);
    for ($k = 0; $k < 32; ++$k) {
	if ((($mask >> (31-$k)) & 1) == 0) {
	    last;
	}
    }
    return $k;
}

sub pretty_net_and_mask ($$) {
    my ($net, $mask) = @_;
    my $prefix_length = netmask_to_prefix_length ($mask);
    my ($firstbyte) = split ('\.', $net);
    my $classful_prefix_length
	= $firstbyte < 128 ? 8
	    : $firstbyte < 192 ? 16
		: $firstbyte < 224 ? 24 : -1;
    ($use_classful_defaults
     && $prefix_length == $classful_prefix_length)
	? $net : $net.'/'.$prefix_length;
}

sub get_if_descrs ($) {
    my ($session) = @_;
    my %descrs = ();

    $session->map_table ([$ifDescr],
	 sub { my ($index, $descr) = @_;
	       $descrs{$index} = pretty_print ($descr);
	   });
    \%descrs;
}
