#!/usr/local/bin/perl
#
# File_________: snmpwalk_h.pl
# Date_________: 23.05.2001
# Author_______: Laurent Girod  / Philip Morris Products S.A. / Neuchatel / Switzerland
# Description__: Example of uses of the new snmpwalk_hash function in SNMP_util
#                With snmpwalkhash, you can customize as you like your
#                results, in a hash of hashes,
#                by oid names, oid numbers, instances, like:
#                   $hash{$host}{$name}{$inst} = $value;
#                   $hash{$host}{$oid}{$inst} = $value;
#                   $hash{$name}{$inst} = $value;
#                   $hash{$oid}{$inst} = $value;
#                   $hash{$oid.'.'.$inst} = $value;
#                   $hash{$inst} = $value;
#                   ...
# Needed_______: ActiveState Perl 620 from www.perl.com
# Modifications: 
#
########################################################################################################

use BER;
use SNMP_util "0.89";

$BER::pretty_print_timeticks = 0;	# Uptime in absolute value

my $host = 'public@127.0.0.1';

#
#	Example 1: 
#
my $oid_name = 'system';

print "\nCollecting [$oid_name]\n";
my %ret_hash = &snmpwalkhash($host, \&my_hash_with_host, $oid_name);
foreach $oid (sort keys %{$ret_hash{$host}})
{
	foreach my $inst (sort { $a <=> $b } keys %{$ret_hash{$host}{$oid}})
	{
		printf("%20s\t: %-15s %3s = %s\n", $host, $oid, $inst, $ret_hash{$host}{$oid}{$inst});
	}
}

#
#	Example 2: 
#
my @oid_names = ('ifSpeed', 'ifPhysAddress', 'ifInOctets', 'ifOutOctets');
	
print "\nCollecting ";
map { print "[$_]\t" } @oid_names;
print "\n";

%ret_hash = ();
%ret_hash = &snmpwalkhash($host, \&my_simple_hash, @oid_names);
foreach $oid (keys %ret_hash)
{
	foreach my $inst (sort { $a <=> $b } keys %{$ret_hash{$oid}})
	{
		printf("%15s %3s = %s\n", $oid, $inst, $ret_hash{$oid}{$inst});
	}
}


#
#	Custom subs , as you like the results
#
sub my_hash_with_host
{
	my ($h_ref, $host, $name, $oid, $inst, $value) = @_;
	$inst =~ s/^\.+//;
	$h_ref->{$host}->{$name}->{$inst} = $value;
}

sub my_simple_hash
{
	my ($h_ref, $host, $name, $oid, $inst, $value) = @_;
	$inst =~ s/^\.+//;
	if ($name =~/ifPhysAddress/)
	{
		my $mac = '';
		map { $mac .= sprintf("%02X",$_) } unpack "CCCCCC", $value;
		$value = $mac;
	}
	$h_ref->{$name}->{$inst} = $value;
}
