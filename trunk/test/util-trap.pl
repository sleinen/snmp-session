#!/usr/local/bin/perl -w

use strict;

use SNMP_util "0.55";

my $ent = '1.3.6.1.4.2946.1.1.1.1';
my $agent = '130.59.4.2';
my $gen = 1;
my $spec = 2;
my @vars = ();

snmptrap ('hctiws@etna', $ent, $agent, $gen, $spec, @vars);
1;
