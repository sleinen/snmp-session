#!/usr/local/bin/perl -w

use strict;

use SNMP_Session;
use BER;

my $switch='localhost';
my $community='hctiws';
my $session=SNMPv2c_Session->open($switch,$community,161);
my $num_results=$session->map_table_4(
    [[1,3,6,1,2,1,1]], # system
    sub {
         #---- Process one line of switch data
         my ($index,$name)=@_;
         $name=pretty_print($name);
         print "$index:$name\n";
    },
    5
);
1;
