#!/usr/local/bin/perl -w

use lib qw(/home/leinen/perl/SNMP_Session-0.80/lib);
use strict;
use SNMP_Session "0.78";
use BER;
#use Socket;

sub usage ();

my @fh_routers = qw(rtrBESW1 rtrBEFH1 rtrZOFH1 rtrBUFH1 rtrMUFH1
		    rtrOEFH1 rtrOLFH1 rtrLUFH1 rtrHOFH1
		    rtrMAFH1 rtrZUSW1 rtrBAFH1 rtrRAFH1 rtrBWFH1
		    rtrBADFH1 rtrZUFH1 rtrWINFH1 rtrWAFH1
		    rtrCHFH1 rtrBUCFH1 rtrLASW1
		    rtrLAFH1 rtrYVFH1 rtrSAIFH1 rtrBIFH1
		    rtrDEFH1 rtrSIFH1 rtrAAFH1
		    rtrDEprof1 rtrZUprof1);

## SNMP doesn't work :-(
##rtrNEFH1 rtrSGFH1
##rtrUNIBA1 rtrVOGEL1 rtrOTTEL1

@fh_routers = qw(rtrDEprof1 rtrZUprof1);

my $oid_ifNumber     = '1.3.6.1.2.1.2.1.0';
my $oid_sysUpTime    = '1.3.6.1.2.1.1.3.0';
my $oid_whyReload    = '1.3.6.1.4.1.9.2.1.2.0';
my $sysName ='1.3.6.1.2.1.1.5.0';
my @oids = ($sysName);
#my @oids = ($oid_ifNumber, $oid_sysUpTime, $oid_whyReload,$sysName);

my $oid_ifDescr =  [1,3,6,1,2,1,2,2,1,2];  
my $oid_ifAdminStatus =  [1,3,6,1,2,1,2,2,1,7];  
my $oid_ifOperStatus =  [1,3,6,1,2,1,2,2,1,8];  
my $oid_ifInOctets =  [1,3,6,1,2,1,2,2,1,10];
my $oid_ifPhysAddress = [1,3,6,1,2,1,2,2,1,6];


#my $oid_atNetAddress =[1,3,6,1,2,1,3,1,1,3];
#my $oid_atIfIndex = [1,3,6,1,2,1,3,1,1,1];
my $ipAdEntAddr=[1,3,6,1,2,1,4,20,1,1];
my $ipAdEntIfIndex= [1,3,6,1,2,1,4,20,1,2];


my $oid_ifHCInOctets = [1,3,6,1,2,1,31,1,1,1,6];
my $oid_ifHCOutOctets = [1,3,6,1,2,1,31,1,1,1,10];

#my $oid_ifInErrors =  [1,3,6,1,2,1,2,2,1,14];  
my $oid_ifOutOctets =  [1,3,6,1,2,1,2,2,1,16];  
#my $oid_ifOutDiscards=[1,3,6,1,2,1,2,2,1,19];
my @oids_table = ($oid_ifDescr, $oid_ifAdminStatus, $oid_ifOperStatus,
		  $oid_ifInOctets, $oid_ifHCInOctets, $oid_ifOutOctets,
		  $oid_ifPhysAddress);

my @oids_atTable =($ipAdEntAddr,$ipAdEntIfIndex);
my %interfaces;
my $community = $ARGV[1] || "hctiws";

foreach my $hostname (@fh_routers) {
    my $session;
    die "Couldn't open SNMP session to $hostname"
	unless ($session = SNMPv2c_Session->open ($hostname, $community, 161));
    $session->{'use_getbulk'}=0;    # 
    
    my $name;
    $name = get_snmp_data($session,@oids);
    $name =~ s/.switch.ch//;
    
#print $name , "\n";

    get_snmp_tabledata($session,1,@oids_table);
    my %ifentry = %interfaces;
    %interfaces= ();

    get_snmp_tabledata($session,0,@oids_atTable);

    my $have_loopback = 0;
    my ($key,$key1);
    foreach $key (keys %ifentry) {
	foreach $key1 (keys %interfaces) {
	    if(($interfaces{$key1}{'admin'} == $key)) {
		my $hostname = $name;
		my $ifname = $ifentry{$key}{'descr'};
		$hostname .= '-'.$ifname, $have_loopback=1
		    unless $ifname eq 'L0';
		printf("%s\tA\t",$hostname,);
		print "$interfaces{$key1}{'descr'}";
		print "\t;shutdown"
		    unless $ifentry{$key}{'oper'}==1;
		print "\n";
	    }
	}
    }
    $session->close ();
    %interfaces = ();
    $name =~ s/^rtr//;
    printf "%s\t\tCNAME\trtr%s\n", $name, $name;
    print ";\n";
}
1;



sub usage () {
  die "usage: $0 host [community]";
}

sub get_snmp_tabledata($$@) {
    my($session,$foo,@oids) = @_;
    my ($value);
    $session->map_table ([  @oids ],
		     sub () {
			 my ($index, $descr, $admin, $oper, $in, $in64, $out, $out64) = @_;
			 grep (defined $_ && ($_=pretty_print $_),
			       ($descr, $admin, $oper, $in, $in64, $out, $out64));
			 #return if( $descr =~ /-cef layer/);
			 #return if( $descr =~ /-atm subif/);
			 #return if( $descr =~ /-atm layer/);
			 if ($foo) {
			     $descr =~ s/-(aal5 layer|atm subif)//;
			     $descr =~ s@[/.]@-@g;
			     $descr =~ s@ATM@A@g;
			     $descr =~ s@Serial@S@g;
			     $descr =~ s@FastEthernet@F@g;
			     $descr =~ s@Ethernet@E@g;
			     $descr =~ s@POS@P@g;
			     $descr =~ s@Loopback@L@g;
			     $descr =~ s@Tunnel@T@g;
			 }
			 $interfaces{$index}{'descr'} = $descr;
			 $interfaces{$index}{'admin'} = $admin;
			 $interfaces{$index}{'oper'}= $oper;
			 $interfaces{$index}{'in'}=$in;
			 $interfaces{$index}{'in64'} =$in64;
			 $interfaces{$index}{'out'} = $out;
			 $interfaces{$index}{'out64'}=$out64;
			 #$interfaces{$index}{'descr'} = $descr; defined $descr ? $descr : 'NaN',
			 
#$interfaces{$index}defined $admin ? $admin : 'NaN',
			 #$interfaces{$index}	 defined $oper ? $oper : 'NaN',
			 #$interfaces{$index}	 defined $in ? $in : 'NaN',
			 #$interfaces{$index}	 defined $in64 ? $in64 : 'NaN',
			 #$interfaces{$index}	 defined $out ? $out : 'NaN',
			 #$interfaces{$index}	 defined $out64 ? $out64 : 'NaN');
			 
			 printf("%3s : %-24s : %2s : %2s : %10s : %16s : %10s : %16s\n",
				 $index,
				 defined $descr ? $descr : 'NaN',
				 defined $admin ? $admin : 'NaN',
				 defined $oper ? $oper : 'NaN',
				 defined $in ? $in : 'NaN',
				 defined $in64 ? $in64 : 'NaN',
				 defined $out ? $out : 'NaN',
				 defined $out64 ? $out64 : 'NaN') if 0;
			


	     });

}

sub get_snmp_data($@) {
    my ($session,@oids) = @_;
    my ($bindings, $binding, $oid, $value);
    grep ( $_ = encode_oid (split (/\./,$_)),  @oids);
    if ($session->get_request_response (@oids)) {
	($bindings) = $session->decode_get_response ($session->{pdu_buffer});

	while ($bindings ne '') {
	    ($binding,$bindings) = &decode_sequence ($bindings);
	    ($oid,$value) = &decode_by_template ($binding, "%O%@");
	    #print &pretty_print ($value), "\n";
	     return &pretty_print($value);
	}
    } else {
	die "No response from agent\n";
    }
}
