#!/usr/local/bin/perl -w
###
### Demonstration code for table walking
###
### This script should serve as an example of how to "correctly"
### traverse the rows of a table.  This functionality is implemented in
### the map_table() subroutine.  The example script displays a few
### columns of the RFC 1213 interface table and Cisco's locIfTable.  The
### tables share the same index, so they can be handled by a single
### invocation of map_table().

require 5.003;

use strict;

use BER;
use SNMP_Session;
use POSIX;			# for exact time
use Curses;

my $host = shift @ARGV || die;
my $community = shift @ARGV || die;

my $desired_interval = 5.0;

my $ifDescr = [1,3,6,1,2,1,2,2,1,2];
my $ifAdminStatus = [1,3,6,1,2,1,2,2,1,7];
my $ifOperStatus = [1,3,6,1,2,1,2,2,1,8];
my $ifInOctets = [1,3,6,1,2,1,2,2,1,10];
my $ifOutOctets = [1,3,6,1,2,1,2,2,1,16];
my $ifInUcastPkts = [1,3,6,1,2,1,2,2,1,11];
my $ifOutUcastPkts = [1,3,6,1,2,1,2,2,1,17];
my $locIfInBitsSec = [1,3,6,1,4,1,9,2,2,1,1,6];
my $locIfOutBitsSec = [1,3,6,1,4,1,9,2,2,1,1,8];
my $locIfDescr = [1,3,6,1,4,1,9,2,2,1,1,28];

my $clock_ticks = POSIX::sysconf( &POSIX::_SC_CLK_TCK );

my $win = new Curses;

my %old;
my $sleep_interval = $desired_interval + 0.0;
my $interval;
my $linecount;

sub out_interface {
    my ($index, $descr, $admin, $oper, $in, $out, $inpkts, $outpkts, $comment) = @_;
    my ($clock) = POSIX::times();
    grep (defined $_ && ($_=pretty_print $_),
	  ($descr, $admin, $oper, $in, $out, $inpkts, $outpkts, $comment));
    $win->clrtoeol ();
    return unless $oper == 1;	# up
    return unless defined $in && defined $out && defined $inpkts && defined $outpkts;
    if (!defined $old{$index}) {
	$win->addstr ($linecount, 0,
		      sprintf ("%2d  %-24s %10s %10s %10s %10s %s\n",
			       $index,
			       defined $descr ? $descr : '',
			       defined $in ? $in : '-',
			       defined $out ? $out : '-',
			       defined $inpkts ? $inpkts : '-',
			       defined $outpkts ? $outpkts : '-',
			       defined $comment ? $comment : ''));
    } else {
	$interval = ($clock-$old{$index}->{'clock'}) * 1.0 / $clock_ticks;
	$win->addstr ($linecount, 0,
		      sprintf ("%2d  %-24s %10.1f %10.1f %10.1f %10.1f %s\n",
			       $index,
			       defined $descr ? $descr : '',
			       defined $in ? ($in-$old{$index}->{'in'})*8/$interval : 0,
			       defined $out ? ($out-$old{$index}->{'out'})*8/$interval : 0,
			       defined $inpkts ? ($inpkts-$old{$index}->{'inpkts'})/$interval : 0,
			       defined $outpkts ? ($outpkts-$old{$index}->{'outpkts'})/$interval : 0,
			       defined $comment ? $comment : ''));
    }
    $old{$index} = {'in' => $in,
		    'out' => $out,
		    'inpkts' => $inpkts,
		    'outpkts' => $outpkts,
		    'clock' => $clock};
    ++$linecount;
    $win->refresh ();
}

$win->erase ();
my $session = SNMP_Session->open ($host, $community, 161)
  || die "Opening SNMP_Session";
while (1) {
    $win->standout();
    $win->addstr (0, 0, sprintf ("%-20s interval %4.1fs",
				 $host,
				 $interval || $desired_interval));
    $win->addstr (1, 0,
		  sprintf ("%2s  %-24s %10s %10s %10s %10s %s\n",
			   "ix", "desc", "inOctets", "outOctets", "inPkts", "outPkts", "alias"));
    $win->clrtoeol ();
    $win->standend();
    $linecount = 2;
    $session->map_table ([$ifDescr,$ifAdminStatus,$ifOperStatus,
			  $ifInOctets,$ifOutOctets,$ifInUcastPkts,$ifOutUcastPkts,$locIfDescr],
			 \&out_interface);
    $sleep_interval -= ($interval - $desired_interval)
	if defined $interval;
    select (undef, undef, undef, $sleep_interval);
}
1;
