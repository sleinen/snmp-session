#!/usr/local/bin/perl -w

use strict;

use SNMP_Session;
use SNMP_util;

sub show_light_trail (@);
sub show_bitmap ($$);

snmpmapOID (qw(amplifierOperStatus 1.3.6.1.4.1.2522.1.5.1.1.0
	       amplifierLastChange 1.3.6.1.4.1.2522.1.5.1.2.0
	       amplifierGain-dB 1.3.6.1.4.1.2522.1.5.1.3.0
	       inputPowerStatus 1.3.6.1.4.1.2522.1.5.1.4.0
	       inputPowerLevel 1.3.6.1.4.1.2522.1.5.1.5.0
	       outputPowerStatus 1.3.6.1.4.1.2522.1.5.1.6.0
	       outputPowerLevel 1.3.6.1.4.1.2522.1.5.1.7.0));

#my @amps = qw(public@muxCE1-A8  
#	       public@muxLS1-A1  
#	       public@muxLS1-A2  
#	       public@muxLS1-A7  
#	       public@muxLS1-A8  
#	       public@muxBE1-A1
#	       public@muxBE1-A2
#	       public@muxBE1-A7
#	       public@muxBE1-A8
#	       public@muxBA1-A1  
#	       public@muxBA1-A2  
#	       public@muxBA1-A7  
#	       public@muxBA1-A8
#	       public@muxEZ1-A1  
#	       public@muxEZ1-A2);

my @eastbound_amps = qw(public@muxCE1-A8  
	      public@muxLS1-A1  
	      public@muxLS1-A8  
	      public@muxBE1-A1
	      public@muxBE1-A8
	      public@muxBA1-A1  
	      public@muxBA1-A8
	      public@muxEZ1-A1);


my @westbound_amps = qw(
	      public@muxEZ1-A2
	      public@muxBA1-A7  
	      public@muxBA1-A2  
	      public@muxBE1-A7
	      public@muxBE1-A2
	      public@muxLS1-A7  
	      public@muxLS1-A2  
			);

my @amps = (@eastbound_amps, @westbound_amps);

for (;;) {
    my $localtime = localtime();
    print "",$localtime,"\n";
    print "\nEastbound:\n";
    show_light_trail (@eastbound_amps);
    print "\nWestbound:\n";
    show_light_trail (@westbound_amps);
    print "-"x 75,"\n";
    sleep (300);
}
1;

sub show_light_trail (@) {
    my @amps = @_;
    printf "%-16s%-8s%-8s\n", "node", "  in pwr", " out pwr";
    printf "%-16s%-8s%-8s\n", "name", "   dbM", "   dbM";
    foreach my $amp (@amps) {
	my ($community,$nodename) = split (/@/,$amp);
	my ($amp_status,
	    $in_status, $in,
	    $out_status, $out)
	    = snmpget ($amp, qw(amplifierOperStatus
					   inputPowerStatus inputPowerLevel
					   outputPowerStatus outputPowerLevel));
	printf "%-16s%8.2f%8.2f\t%-8s%-8s%-8s\n",
	$nodename, $in, $out,
	show_bitmap ($amp_status, 5),
	pretty_power_status ($in_status),
	pretty_power_status ($out_status);
    }
}

sub show_bitmap ($$) {
    my ($bits,$n) = @_;
    my ($k,$result);
    for ($k = 0, $result = ''; $k < $n; ++$k) {
	$result .= (($bits & (1<<$k)) ? '*' : ' ');
    }
    return $result;
}

sub pretty_power_status ($) {
    return (qw(???? ---- minr majr CRIT))[$_[0]];
}
