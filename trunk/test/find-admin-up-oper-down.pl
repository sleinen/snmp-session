#!/usr/local/bin/perl -w

use strict;

use SNMP_util;

sub basename ($ );
sub find_admin_up_oper_down_interfaces ($ );

my $community = 'hctiws';
my @routers = map { basename $_ } </usr/local/rancid/*/configs/{swi,rtr}*>;
my $version = '2c';
my $port = 161;
my $ipv4_only_p = 1;

my $ifDescr = [1,3,6,1,2,1,2,2,1,2];
my $ifAdminStatus = [1,3,6,1,2,1,2,2,1,7];
my $ifOperStatus = [1,3,6,1,2,1,2,2,1,8];

foreach my $router (@routers) {
    find_admin_up_oper_down_interfaces ($router);
}
1;

sub basename ($ ) {
    my $name = $_[0];
    $name =~ s@.*/@@;
    return $name;
}

sub find_admin_up_oper_down_interfaces ($ ) {
    my ($router) = @_;
    my $session =
	($version eq '1' ? SNMPv1_Session->open ($router, $community, $port, undef, undef, undef, undef, $ipv4_only_p)
	 : $version eq '2c' ? SNMPv2c_Session->open ($router, $community, $port, undef, undef, undef, undef, $ipv4_only_p)
	 : die "Unknown SNMP version $version")
	|| die "Opening SNMP_Session";
    $session->map_table ([$ifDescr,$ifAdminStatus,$ifOperStatus],
			 sub () {
			     my ($index, $descr, $admin, $oper) = @_;
			     grep (defined $_ && ($_=BER::pretty_print $_),
				   ($descr, $admin, $oper));
			     print "$router:$descr\n"
				 if ($admin == 1) and ($oper == 2);
			 });
    $session->close
	or warn "trouble closing session to $router";
}
