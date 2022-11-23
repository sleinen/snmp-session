#!/usr/bin/perl -w

use strict;
use warnings;

use BER;
use SNMP_Session "0.96";	# requires map_table_4() and ipv4only

sub usage ($ );

my $version = '2c';

my $port = 161;

my $max_repetitions = 0;

## Whether to select IPv4-only in open().  Can be set using `-4' option.
my $ipv4_only_p = 0;

my $debug = 0;

my $host;

my $community;

my $use_getbulk_p = 1;

my $entPhysicalIndex = [1,3,6,1,2,1,47,1,1,1,1,1];
my $entPhysicalDescr = [1,3,6,1,2,1,47,1,1,1,1,2];
my $entPhysicalVendorType = [1,3,6,1,2,1,47,1,1,1,1,3];
my $entPhysicalContainedIn = [1,3,6,1,2,1,47,1,1,1,1,4];
my $entPhysicalClass = [1,3,6,1,2,1,47,1,1,1,1,5];
my $entPhysicalParentRelPos = [1,3,6,1,2,1,47,1,1,1,1,6];
my $entPhysicalName = [1,3,6,1,2,1,47,1,1,1,1,7];
my $entPhysicalHardwareRev = [1,3,6,1,2,1,47,1,1,1,1,8];
my $entPhysicalFirmwareRev = [1,3,6,1,2,1,47,1,1,1,1,9];
my $entPhysicalSoftwareRev = [1,3,6,1,2,1,47,1,1,1,1,10];
my $entPhysicalSerialNum = [1,3,6,1,2,1,47,1,1,1,1,11];
my $entPhysicalMfgName = [1,3,6,1,2,1,47,1,1,1,1,12];
my $entPhysicalModelName = [1,3,6,1,2,1,47,1,1,1,1,13];
my $entPhysicalAlias = [1,3,6,1,2,1,47,1,1,1,1,14];
my $entPhysicalAssetID = [1,3,6,1,2,1,47,1,1,1,1,15];
my $entPhysicalIsFRU = [1,3,6,1,2,1,47,1,1,1,1,16];
my $entPhysicalMfgDate = [1,3,6,1,2,1,47,1,1,1,1,17];
my $entPhysicalUris = [1,3,6,1,2,1,47,1,1,1,1,18];

my $entSensorType = [1,3,6,1,4,1,9,9,91,1,1,1,1,1];
my $entSensorScale = [1,3,6,1,4,1,9,9,91,1,1,1,1,2];
my $entSensorPrecision = [1,3,6,1,4,1,9,9,91,1,1,1,1,3];
my $entSensorValue = [1,3,6,1,4,1,9,9,91,1,1,1,1,4];
my $entSensorStatus = [1,3,6,1,4,1,9,9,91,1,1,1,1,5];
my $entSensorValueTimeStamp = [1,3,6,1,4,1,9,9,91,1,1,1,1,6];
my $entSensorValueUpdateRate = [1,3,6,1,4,1,9,9,91,1,1,1,1,7];
my $entSensorMeasuredEntity = [1,3,6,1,4,1,9,9,91,1,1,1,1,8];

# : leinen@asama[leinen]; snmptable -v 2c -c hctiws -Ci -Cb ls1 entSensorValueTable | grep -E '\b(4367|8463)\b'
#    4367   watts milli         0   196419     ok   0:0:00:00.00      10 seconds                4097
#    8463   watts milli         0   166576     ok   0:0:00:00.00      10 seconds                8193

while (defined $ARGV[0]) {
    if ($ARGV[0] =~ /^-v/) {
	if ($ARGV[0] eq '-v') {
	    shift @ARGV;
	    usage (1) unless defined $ARGV[0];
	} else {
	    $ARGV[0] = substr($ARGV[0], 2);
	}
	if ($ARGV[0] eq '1') {
	    $version = '1';
	} elsif ($ARGV[0] eq '2c' or $ARGV[0] eq '2') {
	    $version = '2c';
	} else {
	    usage (1);
	}
    } elsif ($ARGV[0] =~ /^-m/) {
	if ($ARGV[0] eq '-m') {
	    shift @ARGV;
	    usage (1) unless defined $ARGV[0];
	} else {
	    $ARGV[0] = substr($ARGV[0], 2);
	}
	if ($ARGV[0] =~ /^[0-9]+$/) {
	    $max_repetitions = $ARGV[0];
	} else {
	    usage (1);
	}
    } elsif ($ARGV[0] =~ /^-p/) {
	if ($ARGV[0] eq '-p') {
	    shift @ARGV;
	    usage (1) unless defined $ARGV[0];
	} else {
	    $ARGV[0] = substr($ARGV[0], 2);
	}
	if ($ARGV[0] =~ /^[0-9]+$/) {
	    $port = $ARGV[0];
	} else {
	    usage (1);
	}
    } elsif ($ARGV[0] eq '-B') {
	$use_getbulk_p = 0;
    } elsif ($ARGV[0] eq '-4') {
	$ipv4_only_p = 1;
    } elsif ($ARGV[0] eq '-h') {
	usage (0);
	exit 0;
    } elsif ($ARGV[0] =~ /^-/) {
	usage (1);
    } else {
	if (!defined $host) {
	    $host = $ARGV[0];
	} elsif (!defined $community) {
	    $community = $ARGV[0];
	} else {
	    usage (1);
	}
    }
    shift @ARGV;
}
defined $host or usage (1);
defined $community or $community = 'public';
usage (1) if $#ARGV >= $[;

my $session =
    ($version eq '1' ? SNMPv1_Session->open ($host, $community, $port, undef, undef, undef, undef, $ipv4_only_p)
     : $version eq '2c' ? SNMPv2c_Session->open ($host, $community, $port, undef, undef, undef, undef, $ipv4_only_p)
     : die "Unknown SNMP version $version")
  || die "Opening SNMP_Session";

### max_repetitions:
###
### We try to be smart about the value of $max_repetitions.  Starting
### with the session default, we use the number of rows in the table
### (returned from map_table_4) to compute the next value.  It should
### be one more than the number of rows in the table, because
### map_table needs an extra set of bindings to detect the end of the
### table.
###
$max_repetitions = $session->default_max_repetitions
    unless $max_repetitions;

my @entity_oids = (
    $entPhysicalDescr,
    $entPhysicalVendorType,
    $entPhysicalContainedIn,
    $entPhysicalClass,
    $entPhysicalParentRelPos,
    $entPhysicalName,
    $entPhysicalHardwareRev,
    $entPhysicalFirmwareRev,
    $entPhysicalSoftwareRev,
    $entPhysicalSerialNum,
    $entPhysicalMfgName,
    $entPhysicalModelName,
    $entPhysicalAlias,
    $entPhysicalAssetID,
    $entPhysicalIsFRU,
    $entPhysicalMfgDate,
    $entPhysicalUris,
    $entSensorType,
    $entSensorScale,
    $entSensorPrecision,
    $entSensorValue,
    $entSensorStatus,
    $entSensorValueTimeStamp,
    $entSensorValueUpdateRate,
    $entSensorMeasuredEntity,
);

my %physical_entity = ();

sub collect_physical_entity(@ ) {
    my ($index, $descr, $vendor_type, $contained_in, $class, $parent_rel_pos,
        $name, $hardware_rev, $firmare_rev, $software_rev, $serial_num,
        $mfg_name, $model_name, $alias, $asset_id, $is_fru, $mfg_date, $uris,
        $sensor_type, $sensor_scale, $sensor_precision,
        $sensor_value, $sensor_status,
        $sensor_value_time_stamp, $sensor_value_update_rate,
        $sensor_measured_entity) = @_;

    grep (defined $_ && ($_=pretty_print $_),
	  ($descr, $class, $name, $alias, $contained_in,
           $sensor_type, $sensor_scale, $sensor_precision,
           $sensor_value, $sensor_status));

    $physical_entity{$index} = {
        'index' => $index,
            'descr' => $descr,
            'class' => $class,
            'name' => $name,
            'alias' => $alias,
            'contained_in' => $contained_in,
            'sensor_type' => $sensor_type,
            'sensor_scale' => $sensor_scale,
            'sensor_precision' => $sensor_precision,
            'sensor_value' => $sensor_value,
            'sensor_status' => $sensor_status,
    };
    # warn("index: $index descr $descr alias $alias class $class\n");
}

my $calls = $session->map_table_4 (\@entity_oids, \&collect_physical_entity, $max_repetitions);

my %power_supplies = ();
foreach my $index (sort keys %physical_entity) {
    my $ent = $physical_entity{$index};
    next unless $ent->{class} == 6;
    $power_supplies{$index} = 1;
}

my %power_supplies_modules_closure = %power_supplies;

my $found_one = 0;
do {
    foreach my $index (sort keys %physical_entity) {
        my $ent = $physical_entity{$index};
        my $contained_in = $ent->{contained_in};
        next unless exists $power_supplies{$contained_in};
        my $class = $ent->{class};
        next unless $class == 9; # We're only interested in modules(9)
        my $descr = $ent->{descr};
        my $alias = $ent->{alias};
        my $name = $ent->{name};
        #warn "Found module child: $index (descr \"$descr\" alias \"$alias\" class $class parent $contained_in)\n";
    }
} while ($found_one);

my $total_watts = 0.0;

foreach my $index (sort keys %physical_entity) {
    my $ent = $physical_entity{$index};
    my $contained_in = $ent->{contained_in};
    next unless exists $power_supplies_modules_closure{$contained_in};
    my $class = $ent->{class};
    next unless $class == 8; # We're only interested in sensors(8)
    my $sensor_type = $ent->{sensor_type};
    next unless $sensor_type == 6; # We're only interested in watts(6)
    my $name = $ent->{name};
    next if ($name =~ /output power/i);
    my $descr = $ent->{descr};
    my $alias = $ent->{alias};
    my $sensor_scale = $ent->{sensor_scale};
    my $sensor_precision = $ent->{sensor_precision};
    my $sensor_value = $ent->{sensor_value};
    my $sensor_status = $ent->{sensor_status};
    my $value = $sensor_value * 10.0**(($sensor_scale-9) * 3);
    $total_watts += $value;
    #warn "Found sensor child: $index (descr \"$descr\" name \"$name\" alias \"$alias\" class $class parent $contained_in sensor_type sensor: [type $sensor_type value $value scale $sensor_scale precision $sensor_precision value $sensor_value status $sensor_status)\n";
}

printf STDOUT ("Total intput power: %6.1fW\n", $total_watts);
1;


sub usage ($) {
    warn <<EOM;
Usage: $0 [-t secs] [-v (1|2c)] [-c] [-l] [-m max] [-4] [-p port] host [community]
       $0 -h

  TODO: Add missing options

  -h           print this usage message and exit.

  -v version   can be used to select the SNMP version.  The default
   	       is SNMPv1, which is what most devices support.  If your box
   	       supports SNMPv2c, you should enable this by passing "-v 2c"
   	       to the script.  SNMPv2c is much more efficient for walking
   	       tables, which is what this tool does.

  -B           do not use get-bulk

  -m max       specifies the maxRepetitions value to use in getBulk requests
               (only relevant for SNMPv2c).

  -4           use only IPv4 addresses, even if host also has an IPv6
               address.  Use this for devices that are IPv6-capable
               but whose SNMP agent doesn\'t listen to IPv6 requests.

  -m port      can be used to specify a non-standard UDP port of the SNMP
               agent (the default is UDP port 161).

  host         hostname or IP address of a router

  community    SNMP community string to use.  Defaults to "public".
EOM
    exit (1) if $_[0];
}
