### - *- mode: Perl -*-
######################################################################
### SNMP_util -- SNMP utilities using SNMP_Session.pm and BER.pm
######################################################################
### Copyright (c) 1998-2001, Mike Mitchell.
###
### This program is free software; you can redistribute it under the
### "Artistic License" included in this distribution (file "Artistic").
######################################################################
### Created by:  Mike Mitchell   <Mike.Mitchell@sas.com>
###
### Contributions and fixes by:
###
### Tobias Oetiker <oetiker@ee.ethz.ch>:  Basic layout
### Simon Leinen <simon@switch.ch>: SNMP_session.pm/BER.pm
### Jeff Allen <jeff.allen@acm.org>: length() of undefined value
### Johannes Demel <demel@zid.tuwien.ac.at>: MIB file parse problem
### Simon Leinen <simon@switch.ch>: more OIDs from Interface MIB
### Jacques Supcik <supcik@ip-plus.net>: Specify local IP, port
### Tobias Oetiker <oetiker@ee.ethz.ch>: HASH as first OID to set SNMP options
### Simon Leinen <simon@switch.ch>: 'undefined port' bug
### Daniel McDonald <dmcdonald@digicontech.com>: request for getbulk support
######################################################################

package SNMP_util;

require 5.004;

use strict;
use vars qw(@ISA @EXPORT $VERSION);
use Exporter;
use Carp;

use BER "0.82";
use SNMP_Session "0.83";
use Socket;

$VERSION = '0.86';

@ISA = qw(Exporter);

@EXPORT = qw(snmpget snmpgetnext snmpwalk snmpset snmptrap snmpgetbulk snmpmapOID snmpMIB_to_OID snmpLoad_OID_Cache snmpQueue_MIB_File);

# The OID numbers from RFC1213 (MIB-II) and RFC1315 (Frame Relay)
# are pre-loaded below.
%SNMP_util::OIDS = 
  (
    'iso' => '1',
    'org' => '1.3',
    'dod' => '1.3.6',
    'internet' => '1.3.6.1',
    'directory' => '1.3.6.1.1',
    'mgmt' => '1.3.6.1.2',
    'mib-2' => '1.3.6.1.2.1',
    'system' => '1.3.6.1.2.1.1',
    'sysDescr' => '1.3.6.1.2.1.1.1.0',
    'sysObjectID' => '1.3.6.1.2.1.1.2',
    'sysUpTime' => '1.3.6.1.2.1.1.3.0',
    'sysUptime' => '1.3.6.1.2.1.1.3.0',
    'sysContact' => '1.3.6.1.2.1.1.4.0',
    'sysName' => '1.3.6.1.2.1.1.5.0',
    'sysLocation' => '1.3.6.1.2.1.1.6.0',
    'sysServices' => '1.3.6.1.2.1.1.7',
    'interfaces' => '1.3.6.1.2.1.2',
    'ifNumber' => '1.3.6.1.2.1.2.1.0',
    'ifTable' => '1.3.6.1.2.1.2.2',
    'ifEntry' => '1.3.6.1.2.1.2.2.1',
    'ifIndex' => '1.3.6.1.2.1.2.2.1.1',
    'ifInOctets' => '1.3.6.1.2.1.2.2.1.10',
    'ifInUcastPkts' => '1.3.6.1.2.1.2.2.1.11',
    'ifInNUcastPkts' => '1.3.6.1.2.1.2.2.1.12',
    'ifInDiscards' => '1.3.6.1.2.1.2.2.1.13',
    'ifInErrors' => '1.3.6.1.2.1.2.2.1.14',
    'ifInUnknownProtos' => '1.3.6.1.2.1.2.2.1.15',
    'ifOutOctets' => '1.3.6.1.2.1.2.2.1.16',
    'ifOutUcastPkts' => '1.3.6.1.2.1.2.2.1.17',
    'ifOutNUcastPkts' => '1.3.6.1.2.1.2.2.1.18',
    'ifOutDiscards' => '1.3.6.1.2.1.2.2.1.19',
    'ifDescr' => '1.3.6.1.2.1.2.2.1.2',
    'ifOutErrors' => '1.3.6.1.2.1.2.2.1.20',
    'ifOutQLen' => '1.3.6.1.2.1.2.2.1.21',
    'ifSpecific' => '1.3.6.1.2.1.2.2.1.22',
    'ifType' => '1.3.6.1.2.1.2.2.1.3',
    'ifMtu' => '1.3.6.1.2.1.2.2.1.4',
    'ifSpeed' => '1.3.6.1.2.1.2.2.1.5',
    'ifPhysAddress' => '1.3.6.1.2.1.2.2.1.6',
    'ifAdminHack' => '1.3.6.1.2.1.2.2.1.7',  
    'ifAdminStatus' => '1.3.6.1.2.1.2.2.1.7',
    'ifOperHack' => '1.3.6.1.2.1.2.2.1.8',             
    'ifOperStatus' => '1.3.6.1.2.1.2.2.1.8',
    'ifLastChange' => '1.3.6.1.2.1.2.2.1.9',
    'at' => '1.3.6.1.2.1.3',
    'atTable' => '1.3.6.1.2.1.3.1',
    'atEntry' => '1.3.6.1.2.1.3.1.1',
    'atIfIndex' => '1.3.6.1.2.1.3.1.1.1',
    'atPhysAddress' => '1.3.6.1.2.1.3.1.1.2',
    'atNetAddress' => '1.3.6.1.2.1.3.1.1.3',
    'ip' => '1.3.6.1.2.1.4',
    'ipForwarding' => '1.3.6.1.2.1.4.1',
    'ipOutRequests' => '1.3.6.1.2.1.4.10',
    'ipOutDiscards' => '1.3.6.1.2.1.4.11',
    'ipOutNoRoutes' => '1.3.6.1.2.1.4.12',
    'ipReasmTimeout' => '1.3.6.1.2.1.4.13',
    'ipReasmReqds' => '1.3.6.1.2.1.4.14',
    'ipReasmOKs' => '1.3.6.1.2.1.4.15',
    'ipReasmFails' => '1.3.6.1.2.1.4.16',
    'ipFragOKs' => '1.3.6.1.2.1.4.17',
    'ipFragFails' => '1.3.6.1.2.1.4.18',
    'ipFragCreates' => '1.3.6.1.2.1.4.19',
    'ipDefaultTTL' => '1.3.6.1.2.1.4.2',
    'ipAddrTable' => '1.3.6.1.2.1.4.20',
    'ipAddrEntry' => '1.3.6.1.2.1.4.20.1',
    'ipAdEntAddr' => '1.3.6.1.2.1.4.20.1.1',
    'ipAdEntIfIndex' => '1.3.6.1.2.1.4.20.1.2',
    'ipAdEntNetMask' => '1.3.6.1.2.1.4.20.1.3',
    'ipAdEntBcastAddr' => '1.3.6.1.2.1.4.20.1.4',
    'ipAdEntReasmMaxSize' => '1.3.6.1.2.1.4.20.1.5',
    'ipRouteTable' => '1.3.6.1.2.1.4.21',
    'ipRouteEntry' => '1.3.6.1.2.1.4.21.1',
    'ipRouteDest' => '1.3.6.1.2.1.4.21.1.1',
    'ipRouteAge' => '1.3.6.1.2.1.4.21.1.10',
    'ipRouteMask' => '1.3.6.1.2.1.4.21.1.11',
    'ipRouteMetric5' => '1.3.6.1.2.1.4.21.1.12',
    'ipRouteInfo' => '1.3.6.1.2.1.4.21.1.13',
    'ipRouteIfIndex' => '1.3.6.1.2.1.4.21.1.2',
    'ipRouteMetric1' => '1.3.6.1.2.1.4.21.1.3',
    'ipRouteMetric2' => '1.3.6.1.2.1.4.21.1.4',
    'ipRouteMetric3' => '1.3.6.1.2.1.4.21.1.5',
    'ipRouteMetric4' => '1.3.6.1.2.1.4.21.1.6',
    'ipRouteNextHop' => '1.3.6.1.2.1.4.21.1.7',
    'ipRouteType' => '1.3.6.1.2.1.4.21.1.8',
    'ipRouteProto' => '1.3.6.1.2.1.4.21.1.9',
    'ipNetToMediaTable' => '1.3.6.1.2.1.4.22',
    'ipNetToMediaEntry' => '1.3.6.1.2.1.4.22.1',
    'ipNetToMediaIfIndex' => '1.3.6.1.2.1.4.22.1.1',
    'ipNetToMediaPhysAddress' => '1.3.6.1.2.1.4.22.1.2',
    'ipNetToMediaNetAddress' => '1.3.6.1.2.1.4.22.1.3',
    'ipNetToMediaType' => '1.3.6.1.2.1.4.22.1.4',
    'ipRoutingDiscards' => '1.3.6.1.2.1.4.23',
    'ipInReceives' => '1.3.6.1.2.1.4.3',
    'ipInHdrErrors' => '1.3.6.1.2.1.4.4',
    'ipInAddrErrors' => '1.3.6.1.2.1.4.5',
    'ipForwDatagrams' => '1.3.6.1.2.1.4.6',
    'ipInUnknownProtos' => '1.3.6.1.2.1.4.7',
    'ipInDiscards' => '1.3.6.1.2.1.4.8',
    'ipInDelivers' => '1.3.6.1.2.1.4.9',
    'icmp' => '1.3.6.1.2.1.5',
    'icmpInMsgs' => '1.3.6.1.2.1.5.1',
    'icmpInTimestamps' => '1.3.6.1.2.1.5.10',
    'icmpInTimestampReps' => '1.3.6.1.2.1.5.11',
    'icmpInAddrMasks' => '1.3.6.1.2.1.5.12',
    'icmpInAddrMaskReps' => '1.3.6.1.2.1.5.13',
    'icmpOutMsgs' => '1.3.6.1.2.1.5.14',
    'icmpOutErrors' => '1.3.6.1.2.1.5.15',
    'icmpOutDestUnreachs' => '1.3.6.1.2.1.5.16',
    'icmpOutTimeExcds' => '1.3.6.1.2.1.5.17',
    'icmpOutParmProbs' => '1.3.6.1.2.1.5.18',
    'icmpOutSrcQuenchs' => '1.3.6.1.2.1.5.19',
    'icmpInErrors' => '1.3.6.1.2.1.5.2',
    'icmpOutRedirects' => '1.3.6.1.2.1.5.20',
    'icmpOutEchos' => '1.3.6.1.2.1.5.21',
    'icmpOutEchoReps' => '1.3.6.1.2.1.5.22',
    'icmpOutTimestamps' => '1.3.6.1.2.1.5.23',
    'icmpOutTimestampReps' => '1.3.6.1.2.1.5.24',
    'icmpOutAddrMasks' => '1.3.6.1.2.1.5.25',
    'icmpOutAddrMaskReps' => '1.3.6.1.2.1.5.26',
    'icmpInDestUnreachs' => '1.3.6.1.2.1.5.3',
    'icmpInTimeExcds' => '1.3.6.1.2.1.5.4',
    'icmpInParmProbs' => '1.3.6.1.2.1.5.5',
    'icmpInSrcQuenchs' => '1.3.6.1.2.1.5.6',
    'icmpInRedirects' => '1.3.6.1.2.1.5.7',
    'icmpInEchos' => '1.3.6.1.2.1.5.8',
    'icmpInEchoReps' => '1.3.6.1.2.1.5.9',
    'tcp' => '1.3.6.1.2.1.6',
    'tcpRtoAlgorithm' => '1.3.6.1.2.1.6.1',
    'tcpInSegs' => '1.3.6.1.2.1.6.10',
    'tcpOutSegs' => '1.3.6.1.2.1.6.11',
    'tcpRetransSegs' => '1.3.6.1.2.1.6.12',
    'tcpConnTable' => '1.3.6.1.2.1.6.13',
    'tcpConnEntry' => '1.3.6.1.2.1.6.13.1',
    'tcpConnState' => '1.3.6.1.2.1.6.13.1.1',
    'tcpConnLocalAddress' => '1.3.6.1.2.1.6.13.1.2',
    'tcpConnLocalPort' => '1.3.6.1.2.1.6.13.1.3',
    'tcpConnRemAddress' => '1.3.6.1.2.1.6.13.1.4',
    'tcpConnRemPort' => '1.3.6.1.2.1.6.13.1.5',
    'tcpInErrs' => '1.3.6.1.2.1.6.14',
    'tcpOutRsts' => '1.3.6.1.2.1.6.15',
    'tcpRtoMin' => '1.3.6.1.2.1.6.2',
    'tcpRtoMax' => '1.3.6.1.2.1.6.3',
    'tcpMaxConn' => '1.3.6.1.2.1.6.4',
    'tcpActiveOpens' => '1.3.6.1.2.1.6.5',
    'tcpPassiveOpens' => '1.3.6.1.2.1.6.6',
    'tcpAttemptFails' => '1.3.6.1.2.1.6.7',
    'tcpEstabResets' => '1.3.6.1.2.1.6.8',
    'tcpCurrEstab' => '1.3.6.1.2.1.6.9',
    'udp' => '1.3.6.1.2.1.7',
    'udpInDatagrams' => '1.3.6.1.2.1.7.1',
    'udpNoPorts' => '1.3.6.1.2.1.7.2',
    'udpInErrors' => '1.3.6.1.2.1.7.3',
    'udpOutDatagrams' => '1.3.6.1.2.1.7.4',
    'udpTable' => '1.3.6.1.2.1.7.5',
    'udpEntry' => '1.3.6.1.2.1.7.5.1',
    'udpLocalAddress' => '1.3.6.1.2.1.7.5.1.1',
    'udpLocalPort' => '1.3.6.1.2.1.7.5.1.2',
    'egp' => '1.3.6.1.2.1.8',
    'egpInMsgs' => '1.3.6.1.2.1.8.1',
    'egpInErrors' => '1.3.6.1.2.1.8.2',
    'egpOutMsgs' => '1.3.6.1.2.1.8.3',
    'egpOutErrors' => '1.3.6.1.2.1.8.4',
    'egpNeighTable' => '1.3.6.1.2.1.8.5',
    'egpNeighEntry' => '1.3.6.1.2.1.8.5.1',
    'egpNeighState' => '1.3.6.1.2.1.8.5.1.1',
    'egpNeighStateUps' => '1.3.6.1.2.1.8.5.1.10',
    'egpNeighStateDowns' => '1.3.6.1.2.1.8.5.1.11',
    'egpNeighIntervalHello' => '1.3.6.1.2.1.8.5.1.12',
    'egpNeighIntervalPoll' => '1.3.6.1.2.1.8.5.1.13',
    'egpNeighMode' => '1.3.6.1.2.1.8.5.1.14',
    'egpNeighEventTrigger' => '1.3.6.1.2.1.8.5.1.15',
    'egpNeighAddr' => '1.3.6.1.2.1.8.5.1.2',
    'egpNeighAs' => '1.3.6.1.2.1.8.5.1.3',
    'egpNeighInMsgs' => '1.3.6.1.2.1.8.5.1.4',
    'egpNeighInErrs' => '1.3.6.1.2.1.8.5.1.5',
    'egpNeighOutMsgs' => '1.3.6.1.2.1.8.5.1.6',
    'egpNeighOutErrs' => '1.3.6.1.2.1.8.5.1.7',
    'egpNeighInErrMsgs' => '1.3.6.1.2.1.8.5.1.8',
    'egpNeighOutErrMsgs' => '1.3.6.1.2.1.8.5.1.9',
    'egpAs' => '1.3.6.1.2.1.8.6',
    'transmission' => '1.3.6.1.2.1.10',
    'frame-relay' => '1.3.6.1.2.1.10.32',
    'frDlcmiTable' => '1.3.6.1.2.1.10.32.1',
    'frDlcmiEntry' => '1.3.6.1.2.1.10.32.1.1',
    'frDlcmiIfIndex' => '1.3.6.1.2.1.10.32.1.1.1',
    'frDlcmiState' => '1.3.6.1.2.1.10.32.1.1.2',
    'frDlcmiAddress' => '1.3.6.1.2.1.10.32.1.1.3',
    'frDlcmiAddressLen' => '1.3.6.1.2.1.10.32.1.1.4',
    'frDlcmiPollingInterval' => '1.3.6.1.2.1.10.32.1.1.5',
    'frDlcmiFullEnquiryInterval' => '1.3.6.1.2.1.10.32.1.1.6',
    'frDlcmiErrorThreshold' => '1.3.6.1.2.1.10.32.1.1.7',
    'frDlcmiMonitoredEvents' => '1.3.6.1.2.1.10.32.1.1.8',
    'frDlcmiMaxSupportedVCs' => '1.3.6.1.2.1.10.32.1.1.9',
    'frDlcmiMulticast' => '1.3.6.1.2.1.10.32.1.1.10',
    'frCircuitTable' => '1.3.6.1.2.1.10.32.2',
    'frCircuitEntry' => '1.3.6.1.2.1.10.32.2.1',
    'frCircuitIfIndex' => '1.3.6.1.2.1.10.32.2.1.1',
    'frCircuitDlci' => '1.3.6.1.2.1.10.32.2.1.2',
    'frCircuitState' => '1.3.6.1.2.1.10.32.2.1.3',
    'frCircuitReceivedFECNs' => '1.3.6.1.2.1.10.32.2.1.4',
    'frCircuitReceivedBECNs' => '1.3.6.1.2.1.10.32.2.1.5',
    'frCircuitSentFrames' => '1.3.6.1.2.1.10.32.2.1.6',
    'frCircuitSentOctets' => '1.3.6.1.2.1.10.32.2.1.7',
    'frOutOctets' => '1.3.6.1.2.1.10.32.2.1.7',
    'frCircuitReceivedFrames' => '1.3.6.1.2.1.10.32.2.1.8',
    'frCircuitReceivedOctets' => '1.3.6.1.2.1.10.32.2.1.9',
    'frInOctets' => '1.3.6.1.2.1.10.32.2.1.9',
    'frCircuitCreationTime' => '1.3.6.1.2.1.10.32.2.1.10',
    'frCircuitLastTimeChange' => '1.3.6.1.2.1.10.32.2.1.11',
    'frCircuitCommittedBurst' => '1.3.6.1.2.1.10.32.2.1.12',
    'frCircuitExcessBurst' => '1.3.6.1.2.1.10.32.2.1.13',
    'frCircuitThroughput' => '1.3.6.1.2.1.10.32.2.1.14',
    'frErrTable' => '1.3.6.1.2.1.10.32.3',
    'frErrEntry' => '1.3.6.1.2.1.10.32.3.1',
    'frErrIfIndex' => '1.3.6.1.2.1.10.32.3.1.1',
    'frErrType' => '1.3.6.1.2.1.10.32.3.1.2',
    'frErrData' => '1.3.6.1.2.1.10.32.3.1.3',
    'frErrTime' => '1.3.6.1.2.1.10.32.3.1.4',
    'frame-relay-globals' => '1.3.6.1.2.1.10.32.4',
    'frTrapState' => '1.3.6.1.2.1.10.32.4.1',
    'snmp' => '1.3.6.1.2.1.11',
    'snmpInPkts' => '1.3.6.1.2.1.11.1',
    'snmpInBadValues' => '1.3.6.1.2.1.11.10',
    'snmpInReadOnlys' => '1.3.6.1.2.1.11.11',
    'snmpInGenErrs' => '1.3.6.1.2.1.11.12',
    'snmpInTotalReqVars' => '1.3.6.1.2.1.11.13',
    'snmpInTotalSetVars' => '1.3.6.1.2.1.11.14',
    'snmpInGetRequests' => '1.3.6.1.2.1.11.15',
    'snmpInGetNexts' => '1.3.6.1.2.1.11.16',
    'snmpInSetRequests' => '1.3.6.1.2.1.11.17',
    'snmpInGetResponses' => '1.3.6.1.2.1.11.18',
    'snmpInTraps' => '1.3.6.1.2.1.11.19',
    'snmpOutPkts' => '1.3.6.1.2.1.11.2',
    'snmpOutTooBigs' => '1.3.6.1.2.1.11.20',
    'snmpOutNoSuchNames' => '1.3.6.1.2.1.11.21',
    'snmpOutBadValues' => '1.3.6.1.2.1.11.22',
    'snmpOutGenErrs' => '1.3.6.1.2.1.11.24',
    'snmpOutGetRequests' => '1.3.6.1.2.1.11.25',
    'snmpOutGetNexts' => '1.3.6.1.2.1.11.26',
    'snmpOutSetRequests' => '1.3.6.1.2.1.11.27',
    'snmpOutGetResponses' => '1.3.6.1.2.1.11.28',
    'snmpOutTraps' => '1.3.6.1.2.1.11.29',
    'snmpInBadVersions' => '1.3.6.1.2.1.11.3',
    'snmpEnableAuthenTraps' => '1.3.6.1.2.1.11.30',
    'snmpInBadCommunityNames' => '1.3.6.1.2.1.11.4',
    'snmpInBadCommunityUses' => '1.3.6.1.2.1.11.5',
    'snmpInASNParseErrs' => '1.3.6.1.2.1.11.6',
    'snmpInTooBigs' => '1.3.6.1.2.1.11.8',
    'snmpInNoSuchNames' => '1.3.6.1.2.1.11.9',
    'ifName' => '1.3.6.1.2.1.31.1.1.1.1',
    'ifInMulticastPkts' => '1.3.6.1.2.1.31.1.1.1.2',
    'ifInBroadcastPkts' => '1.3.6.1.2.1.31.1.1.1.3',
    'ifOutMulticastPkts' => '1.3.6.1.2.1.31.1.1.1.4',
    'ifOutBroadcastPkts' => '1.3.6.1.2.1.31.1.1.1.5',
    'ifHCInOctets' => '1.3.6.1.2.1.31.1.1.1.6',
    'ifHCInUcastPkts' => '1.3.6.1.2.1.31.1.1.1.7',
    'ifHCInMulticastPkts' => '1.3.6.1.2.1.31.1.1.1.8',
    'ifHCInBroadcastPkts' => '1.3.6.1.2.1.31.1.1.1.9',
    'ifHCOutOctets' => '1.3.6.1.2.1.31.1.1.1.10',
    'ifHCOutUcastPkts' => '1.3.6.1.2.1.31.1.1.1.11',
    'ifHCOutMulticastPkts' => '1.3.6.1.2.1.31.1.1.1.12',
    'ifHCOutBroadcastPkts' => '1.3.6.1.2.1.31.1.1.1.13',
    'ifLinkUpDownTrapEnable' => '1.3.6.1.2.1.31.1.1.1.14',
    'ifHighSpeed' => '1.3.6.1.2.1.31.1.1.1.15',
    'ifPromiscuousMode' => '1.3.6.1.2.1.31.1.1.1.16',
    'ifConnectorPresent' => '1.3.6.1.2.1.31.1.1.1.17',
    'ifAlias' => '1.3.6.1.2.1.31.1.1.1.18',
    'ifCounterDiscontinuityTime' => '1.3.6.1.2.1.31.1.1.1.19',
    'experimental' => '1.3.6.1.3',
    'private' => '1.3.6.1.4',
    'enterprises' => '1.3.6.1.4.1',
  );

my $agent_start_time = time;

undef $SNMP_util::Host;
undef $SNMP_util::Session;
undef $SNMP_util::Version;
undef $SNMP_util::LHost;
$SNMP_util::Debug = 0;
$SNMP_util::CacheFile = "OID_cache.txt";
$SNMP_util::CacheLoaded = 0;

srand(time|$$);

### Prototypes
sub snmpget ($@);
sub snmpgetnext ($@);
sub snmpopen ($$$);
sub snmpwalk ($@);
sub snmpset ($@);
sub snmptrap ($$$$$@);
sub snmpgetbulk ($$$@);
sub toOID (@);
sub snmpmapOID (@);
sub snmpMIB_to_OID ($);
sub encode_oid_with_errmsg ($);
sub Check_OID ($);
sub snmpLoad_OID_Cache ($);
sub snmpQueue_MIB_File (@);

sub version () { $VERSION; }

#
# Start an snmp session
#
sub snmpopen ($$$) {
  my($host, $type, $vars) = @_;
  my($nhost, $port, $community, $lhost, $lport, $nlhost);
  my($timeout, $retries, $backoff, $version);

  $type = 0 if (!defined($type));
  $community = "public";
  $nlhost = "";

  ($community, $host) = ($1, $2) if ($host =~ /^(.*)@([^@]+)$/);
  ($host, $port, $timeout, $retries, $backoff, $version) = split(':', $host, 6)
    if ($host =~ /:/);
  $version = '1' unless defined $version;
  undef($port) if (defined($port) && length($port) <= 0);
  if (defined($port) && ($port =~ /^([^!]*)!(.*)$/))
  {
    ($port, $lhost) = ($1, $2);
    $nlhost = $lhost;
    ($lhost, $lport) = ($1, $2) if ($lhost =~ /^(.*)!(.*)$/);
    undef($lhost) if (defined($lhost) && (length($lhost) <= 0));
    undef($lport) if (defined($lport) && (length($lport) <= 0));
  }
  $port = 162 if ($type == 1 && !defined($port));
  $nhost = "$community\@$host";
  $nhost .= ":" . $port if (defined($port));

  if ((!defined($SNMP_util::Session))
    || ($SNMP_util::Host ne $nhost)
    || ($SNMP_util::Version ne $version)
    || ($SNMP_util::LHost ne $nlhost))
  {
    if (defined($SNMP_util::Session))
    {
      $SNMP_util::Session->close();    
      undef $SNMP_util::Session;
      undef $SNMP_util::Host;
      undef $SNMP_util::Version;
      undef $SNMP_util::LHost;
    }
    $SNMP_util::Session = ($version =~ /^2c?$/i)
      ? SNMPv2c_Session->open($host, $community, $port, undef,
				$lport, undef, $lhost)
      : SNMP_Session->open($host, $community, $port, undef,
				$lport, undef, $lhost);
    ($SNMP_util::Host = $nhost, $SNMP_util::Version = $version,
      $SNMP_util::LHost = $nlhost) if defined($SNMP_util::Session);
  }

  if (defined($SNMP_util::Session))
  {
    if (ref $vars->[0] eq 'HASH')
    {
	my $opts = shift @$vars;
	foreach $type (keys %$opts)
	{
	    if (exists $SNMP_util::Session->{$type})
	    {
		if ($type eq 'timeout')
		{
		    $SNMP_util::Session->set_timeout($opts->{$type});
		}
		elsif ($type eq 'retries')
		{
		    $SNMP_util::Session->set_retries($opts->{$type});
		}
		elsif ($type eq 'backoff')
		{
		    $SNMP_util::Session->set_backoff($opts->{$type});
		}
		else
		{
		    $SNMP_util::Session->{$type} = $opts->{$type};
		}
	    }
	    else
	    {
		carp "SNMPopen Unknown SNMP Option Key '$type'\n"
		    unless ($SNMP_Session::suppress_warnings > 1);
	    }
	}
    }
    $SNMP_util::Session->set_timeout($timeout)
      if (defined($timeout) && (length($timeout) > 0));
    $SNMP_util::Session->set_retries($retries)
      if (defined($retries) && (length($retries) > 0));
    $SNMP_util::Session->set_backoff($backoff)
      if (defined($backoff) && (length($backoff) > 0));
  }
  return $SNMP_util::Session;
}


#
# A restricted snmpget.
#
sub snmpget ($@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding, $value, $oid, @retvals);
  my $session;

  $session = &snmpopen($host, 0, \@vars);
  if (!defined($session)) {
    carp "SNMPGET Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = &toOID(@vars);
  return undef unless defined $enoid[0];

  if ($session->get_request_response(@enoid)) {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response($response);
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
      my $tempo = pretty_print($value);
      push @retvals, $tempo;
    }
    return(@retvals);
  }
  $var = join(' ', @vars);
  carp "SNMPGET Problem for $var on $host\n"
    unless ($SNMP_Session::suppress_warnings > 1);
  return undef;
}

#
# A restricted snmpgetnext.
#
sub snmpgetnext ($@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding);
  my($value, $upoid, $oid, @retvals);
  my($noid, $ok);
  my $session;

  $session = &snmpopen($host, 0, \@vars);
  if (!defined($session)) {
    carp "SNMPGETNEXT Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = &toOID(@vars);

  undef @vars;
  undef @retvals;
  foreach $noid (@enoid)
  {
    $upoid = pretty_print($noid);
    push(@vars, $upoid);
  }
  if ($session->getnext_request_response(@enoid))
  {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response($response);
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
      my $tempo = pretty_print($oid);
	my $tempv = pretty_print($value);
	push @retvals, "$tempo:$tempv";
      }
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    carp "SNMPGETNEXT Problem for $var on $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }
}

#
# A restricted snmpwalk.
#
sub snmpwalk ($@) {
  my($host, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding);
  my($value, $upoid, $oid, @retvals);
  my($got, @nnoid, $noid, $ok);
  my $session;
  my(%soid);

  $session = &snmpopen($host, 0, \@vars);
  if (!defined($session)) {
    carp "SNMPWALK Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = toOID(@vars);

  $got = 0;
  @nnoid = @enoid;
  undef @vars;
  foreach $noid (@enoid)
  {
    $upoid = pretty_print($noid);
    push(@vars, $upoid);
  }
  while(($SNMP_util::Version ne '1' && $session->{'use_getbulk'})
	? $session->getbulk_request_response(0, $session->default_max_repetitions(), @nnoid)
	: $session->getnext_request_response(@nnoid))
  {
    $got = 1;
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response($response);
    undef @nnoid;
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
      $ok = 0;
      my $tempo = pretty_print($oid);
      foreach $noid (@vars)
      {
	if ($tempo =~ /^$noid\./ || $tempo eq $noid )
	{
	  $ok = 1;
	  $upoid = $noid;
	  last;
	}
      }
      if ($ok)
      {
	my $tmp = encode_oid_with_errmsg ($tempo);
	return undef unless defined $tmp;
	$soid{$upoid} = $tmp;
	my $tempv = pretty_print($value);
	$tempo=~s/^$upoid\.//;
	push @retvals, "$tempo:$tempv";
      }
    }
    @nnoid = values(%soid);
    undef %soid;
    last if ($#nnoid < 0);
  }
  if ($got)
  {
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    carp "SNMPWALK Problem for $var on $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }
}

#
# A restricted snmpset.
#
sub snmpset($@) {
    my($host, @vars) = @_;
    my(@enoid, $response, $bindings, $binding);
    my($oid, @retvals, $type, $value);
    my $session;

    $session = &snmpopen($host, 0, \@vars);
    if (!defined($session))
    {
	carp "SNMPSET Problem for $host\n"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }

    while(@vars)
    {
	($oid) = toOID((shift @vars));
	$type  = shift @vars;
	$value = shift @vars;
	if ($type =~ /string/i)
	{
	    $value = encode_string($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /ipaddr/i)
	{
	    $value = encode_ip_address($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /int/i)
	{
	    $value = encode_int($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /oid/i)
	{
	    my $tmp = encode_oid_with_errmsg($value);
	    return undef unless defined $tmp;
	    push @enoid, [$oid,$tmp];
	}
	else
	{
	    carp "unknown SNMP type: $type\n"
		unless ($SNMP_Session::suppress_warnings > 1);
	    return undef;
	}
    }
    if ($session->set_request_response(@enoid))
    {
	$response = $session->pdu_buffer;
	($bindings) = $session->decode_get_response($response);
	while ($bindings)
	{
	    ($binding, $bindings) = decode_sequence($bindings);
	    ($oid, $value) = decode_by_template($binding, "%O%@");
	    my $tempo = pretty_print($value);
	    push @retvals, $tempo;
	}
	return (@retvals);
    }
    return undef;
}

#
# Send an SNMP trap
#
sub snmptrap($$$$$@) {
    my($host, $ent, $agent, $gen, $spec, @vars) = @_;
    my($oid, @retvals, $type, $value);
    my(@enoid);
    my $session;

    $session = &snmpopen($host, 1, \@vars);
    if (!defined($session))
    {
	carp "SNMPTRAP Problem for $host\n"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }

    if ($agent =~ /^\d+\.\d+\.\d+\.\d+(.*)/ )
    {
	$agent = pack("C*", split /\./, $agent);
    }
    else
    {
	$agent = inet_aton($agent);
    }
    push @enoid, toOID(($ent));
    push @enoid, encode_ip_address($agent);
    push @enoid, encode_int($gen);
    push @enoid, encode_int($spec);
    push @enoid, encode_timeticks((time-$agent_start_time) * 100);
    while(@vars)
    {
	($oid) = toOID((shift @vars));
	$type  = shift @vars;
	$value = shift @vars;
	if ($type =~ /string/i)
	{
	    $value = encode_string($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /ipaddr/i)
	{
	    $value = encode_ip_address($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /int/i)
	{
	    $value = encode_int($value);
	    push @enoid, [$oid,$value];
	}
	elsif ($type =~ /oid/i)
	{
	    my $tmp = encode_oid_with_errmsg($value);
	    return undef unless defined $tmp;
	    push @enoid, [$oid,$tmp];
	}
	else
	{
	    carp "unknown SNMP type: $type\n"
		unless ($SNMP_Session::suppress_warnings > 1);
	    return undef;
	}
    }
    return($session->trap_request_send(@enoid));
}

#
# A restricted snmpgetbulk.
#
sub snmpgetbulk ($$$@) {
  my($host, $nr, $mr, @vars) = @_;
  my(@enoid, $var, $response, $bindings, $binding);
  my($value, $upoid, $oid, @retvals);
  my($noid, $ok);
  my $session;

  $session = &snmpopen($host, 0, \@vars);
  if (!defined($session)) {
    carp "SNMPGETBULK Problem for $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }

  @enoid = &toOID(@vars);

  undef @vars;
  undef @retvals;
  foreach $noid (@enoid)
  {
    $upoid = pretty_print($noid);
    push(@vars, $upoid);
  }
  if ($session->getbulk_request_response($nr, $mr, @enoid))
  {
    $response = $session->pdu_buffer;
    ($bindings) = $session->decode_get_response($response);
    while ($bindings) {
      ($binding, $bindings) = decode_sequence($bindings);
      ($oid, $value) = decode_by_template($binding, "%O%@");
      my $tempo = pretty_print($oid);
	my $tempv = pretty_print($value);
	push @retvals, "$tempo:$tempv";
      }
    return (@retvals);
  }
  else
  {
    $var = join(' ', @vars);
    carp "SNMPGETBULK Problem for $var on $host\n"
      unless ($SNMP_Session::suppress_warnings > 1);
    return undef;
  }
}

#
#  Given an OID in either ASN.1 or mixed text/ASN.1 notation, return an
#  encoded OID.
#

sub toOID(@)
{
    my(@vars) = @_;
    my($oid, $var, $tmp, $tmpv, @retvar);

    undef @retvar;
    foreach $var (@vars)
    {
	($oid, $tmp) = &Check_OID($var);
	if (!$oid && $SNMP_util::CacheLoaded == 0)
	{
	    $tmp = $SNMP_Session::suppress_warnings;
	    $SNMP_Session::suppress_warnings = 1000;

	    &snmpLoad_OID_Cache($SNMP_util::CacheFile);

	    $SNMP_util::CacheLoaded = 1;
	    $SNMP_Session::suppress_warnings = $tmp;

	    ($oid, $tmp) = &Check_OID($var);
	}
	while (!$oid && $#SNMP_util::MIB_Files >= 0)
	{
	    $tmp = $SNMP_Session::suppress_warnings;
	    $SNMP_Session::suppress_warnings = 1000;

	    snmpMIB_to_OID(shift(@SNMP_util::MIB_Files));

	    $SNMP_Session::suppress_warnings = $tmp;

	    ($oid, $tmp) = &Check_OID($var);
	    if ($oid)
	    {
		open(CACHE, ">>$SNMP_util::CacheFile");
		print CACHE "$tmp\t$oid\n";
		close(CACHE);
	    }
	}
	if ($oid) {
	    $var =~ s/^$tmp/$oid/;
	} else {
	    carp "Unknown SNMP var $var\n"
		unless ($SNMP_Session::suppress_warnings > 1);
	    next;
	}
	print "toOID: $var\n" if $SNMP_util::Debug;
	$tmp = encode_oid_with_errmsg($var);
	return undef unless defined $tmp;
	push(@retvar, $tmp);
    }
    return @retvar;
}

#
#  Add passed-in text, OID pairs to the OID mapping table.
#
sub snmpmapOID(@)
{
    my(@vars) = @_;
    my($oid, $txt, $ind);

    $ind = 0;
    while($ind <= $#vars)
    {
	$txt = $vars[$ind++];
	next unless($txt =~ /^(([a-z][a-z\d\-]*\.)*([a-z][a-z\d\-]*))$/i);

	$oid = $vars[$ind++];
	next unless($oid =~ /^((\d+.)*\d+)$/);

	$SNMP_util::OIDS{$txt} = $oid;
	print "snmpmapOID: $txt => $oid\n" if $SNMP_util::Debug;
    }
    return undef;
}

#
# Open the passed-in file name and read it in to populate
# the cache of text-to-OID map table.  It expects lines
# with two fields, the first the textual string like "ifInOctets",
# and the second the OID value, like "1.3.6.1.2.1.2.2.1.10".
#
# blank lines and anything after a '#' or between '--' is ignored.
#
sub snmpLoad_OID_Cache ($)
{
    my($arg) = @_;
    my($txt, $oid);

    if (!open(CACHE, $arg))
    {
	carp "snmpLoad_OID_Cache: Can't open $arg: $!"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return -1;
    }

    while(<CACHE>)
    {
	s/#.*//;
	s/--.*--//g;
	s/--.*//;
	next if (/^$/);
	next unless (/\s/);
	chop;
	($txt, $oid) = split(' ', $_, 2);
	&snmpmapOID($txt, $oid);
    }
    close(CACHE);
    return 0;
}

#
# Check to see if an OID is in the text-to-OID cache.
# Returns the OID and the corresponding text as two separate
# elements.
#
sub Check_OID ($)
{
    my($var) = @_;
    my($tmp, $tmpv, $oid);

    if ($var =~ /^(([a-z][a-z\d\-]*\.)*([a-z][a-z\d\-]*))/i)
    {
	$tmp = $&;
	$tmpv = $tmp;
	for (;;) {
	    last if defined($SNMP_util::OIDS{$tmpv});
	    last if !($tmpv =~ s/^[^\.]*\.//);
	}
	$oid = $SNMP_util::OIDS{$tmpv};
	if ($oid) {
	    return ($oid, $tmp);
	} else {
	    return undef;
	}
    }
    return ($var, $var);
}

#
# Save the passed-in list of MIB files until an OID can't be
# found in the existing table.  At that time the MIB file will
# be loaded, and the lookup attempted again.
#
sub snmpQueue_MIB_File (@)
{
    my(@files) = @_;
    my($file);

    foreach $file (@files)
    {
	push(@SNMP_util::MIB_Files, $file);
    }
}


#
# Read in the passed list of MIB files, parsing them
# for their text-to-OID mappings
#
sub snmpMIB_to_OID ($)
{
    my($arg) = @_;
    my($quote, $buf, $var, $code, $val, $tmp, $tmpv, $strt);
    my($ret);
    my(%Link) = (
	'org' => 'iso',
	'dod' => 'org',
	'internet' => 'dod',
	'directory' => 'internet',
	'mgmt' => 'internet',
	'mib-2' => 'mgmt',
	'experimental' => 'internet',
	'private' => 'internet',
	'enterprises' => 'private',
    );


    if (!open(MIB, $arg))
    {
	carp "snmpMIB_to_OID: Can't open $arg: $!"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return -1;
    }
    print "snmpMIB_to_OID: loading $arg\n" if $SNMP_util::Debug;
    $ret = 0;
    while(<MIB>)
    {
	s/--.*--//g;		# throw away comments (-- anything --)
	s/--.*//;		# throw away comments (-- anything EOL)
	if ($quote)
	{
	    next unless /"/;
	    $quote = 0;
	}
	chop;
#
#	$buf = "$buf $_";
# Previous line removed (and following replacement)
# suggested by Brian Reichert, reichert@numachi.com
#
	$buf .= ' ' . $_;
	$buf =~ s/\s+/ /g;

	if ($buf =~ / DEFINITIONS ::= BEGIN/)
	{
	    undef %Link;
	    %Link = (
		'org' => 'iso',
		'dod' => 'org',
		'internet' => 'dod',
		'directory' => 'internet',
		'mgmt' => 'internet',
		'mib-2' => 'mgmt',
		'experimental' => 'internet',
		'private' => 'internet',
		'enterprises' => 'private',
	    );
	}

	$buf =~ s/OBJECT-TYPE/OBJECT IDENTIFIER/;
	$buf =~ s/OBJECT-IDENTITY/OBJECT IDENTIFIER/;
	$buf =~ s/MODULE-IDENTITY/OBJECT IDENTIFIER/;
	$buf =~ s/ IMPORTS .*\;//;
	$buf =~ s/ SEQUENCE {.*}//;
	$buf =~ s/ SYNTAX .*//;
	$buf =~ s/ [\w-]+ ::= OBJECT IDENTIFIER//;
	$buf =~ s/ OBJECT IDENTIFIER .* ::= {/ OBJECT IDENTIFIER ::= {/;
	$buf =~ s/".*"//;
	if ($buf =~ /"/)
	{
	    $quote = 1;
	}

	if ($buf =~ / ([\w\-]+) OBJECT IDENTIFIER ::= {([^}]+)}/) {
	    $var = $1;
	    $buf = $2;
	    undef $val;
	    $buf =~ s/ +$//;
	    ($code, $val) = split(' ', $buf, 2);

	    if (!defined($val) || (length($val) <= 0))
	    {
		$SNMP_util::OIDS{$var} = $code;
		$ret++;
		print "'$var' => '$code'\n" if $SNMP_util::Debug;
	    }
	    else
	    {
		$strt = $code;

		while($val =~ / /)
		{
		    ($tmp, $val) = split(' ', $val, 2);
		    if ($tmp =~ /([\w\-]+)\((\d+)\)/)
		    {
			$tmp = $1;
			$tmpv = "$SNMP_util::OIDS{$strt}.$2";
			$Link{$tmp} = $strt;
			if (defined($SNMP_util::OIDS{$tmp}))
			{
			    if ($tmpv ne $SNMP_util::OIDS{$tmp})
			    {
				$strt = "$strt.$tmp";
				$SNMP_util::OIDS{$strt} = $tmpv;
				$ret++;
			    }
			}
			else
			{
			    $SNMP_util::OIDS{$tmp} = $tmpv;
			    $ret++;
			    $strt = $tmp;
			}
		    }
		}

		if (!defined($SNMP_util::OIDS{$strt}))
		{
		    carp "snmpMIB_to_OID: $arg: \"$strt\" prefix unknown, load the parent MIB first.\n"
			unless ($SNMP_Session::suppress_warnings > 1);
		}
		$Link{$var} = $strt;
		$val = "$SNMP_util::OIDS{$strt}.$val";
		if (defined($SNMP_util::OIDS{$var}))
		{
		    if ($val ne $SNMP_util::OIDS{$var})
		    {
			$var = "$strt.$var";
		    }
		}

		$SNMP_util::OIDS{$var} = $val;
		$ret++;

		print "'$var' => '$val'\n" if $SNMP_util::Debug;
	    }
	    undef $buf;
	}
    }
    close(MIB);
    return $ret;
}

sub encode_oid_with_errmsg ($) {
    my ($oid) = @_;
    my $tmp = encode_oid(split(/\./, $oid));
    if (! defined $tmp) {
	carp "cannot encode Object ID $oid: $BER::errmsg"
	    unless ($SNMP_Session::suppress_warnings > 1);
	return undef;
    }
    return $tmp;
}

1;
