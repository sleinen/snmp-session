use BER;
require 'SNMP_Session.pm';

# Set $host to the name of the host whose SNMP agent you want
# to talk to.  Set $community to the community name under
# which you want to talk to the agent.	Set port to the UDP
# port on which the agent listens (usually 161).

$routerfile = 'd:/mrtg/routers';
open(INFO, $routerfile);
@routers = <INFO>;
$redline=10;
$yellowline=5;


print <<"TEXT";    
 <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
 <html>
 <head>
 <meta http-equiv="Content-Type"
 content="text/html; charset=iso-8859-1">
 <title>WAN Routers at a glance</title>
 </head>

 <body background="/images/background.gif">
<table border="0" cellpadding="0" cellspacing="1" width="80%">
    <tr>
        <td align="right" rowspan="2"><img
        src="../images/pushme2.gif" width="150" height="159"></td>
        <td colspan="2"><p align="center"><font size="5"
        face="Bookman Old Style"><strong>WAN Routers at a Glance<br>
        </strong></font><font size="4" face="Bookman Old
Style"><strong>Technical
        Team Only</strong></font></p>
        </td>
    </tr>
</table>
<br>
TEXT
@results2=();
for ($currouter=0; $currouter < $#routers; $currouter++) {

$host=@routers[$currouter];
$community = "public";
$port = "161";
$path = 'i:/inetpub/wwwroot/stats/';

$session = SNMP_Session->open ($host, $community, $port)
    || die "couldn't open SNMP session to $host";

# Set $oid1, $oid2... to the BER-encoded OIDs of the MIB
# variables you want to get.

$oid1 = encode_oid (1, 3, 6, 1, 2, 1, 2, 1, 0);
$oid2 = encode_oid (1, 3, 6, 1, 2, 1, 1, 5, 0);
# Cisco CPU OID
$oid3 = encode_oid (1, 3, 6, 1, 4,1,9,2,1,58,0);
if ($session->get_request_response ($oid1,$oid2,$oid3)) {
    ($bindings) = $session->decode_get_response ($session->{pdu_buffer});
    while ($bindings ne '') {
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$interfaces=pretty_print ($value);
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$sysname=pretty_print ($value);
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$cpupercent=pretty_print ($value);
    }
} else {
    die "No response from agent on $host";
}
print <<TEXT;

 <div align="left"><left>

 <table border="1" cellpadding="0" cellspacing="1" width=80%>
<TR> <td colspan=
TEXT
@results = ();
@outhead=();
@outvalue=();
@outhead[0]="CPU";
if ($cpupercent>$redline){
	    $graphic="<img src = red.gif>";
	  } elsif ($cpupercent>$yellowline) {
	    $graphic="<img src = yellow.gif>";
	  } else {
	    $graphic="<img src = green.gif>";
	  }
@outvalue[0]=$graphic;
$a=1;
for ($i=1; $i <= $interfaces; $i++) {
$oid1=encode_oid(1,3, 6, 1, 2, 1, 2, 2, 1 ,2, $i);
$oid2=encode_oid(1,3, 6, 1, 2, 1, 2, 2, 1 ,8, $i);
$oid3=encode_oid(1,3, 6, 1, 2, 1, 2, 2, 1 ,5, $i);
if ($session->get_request_response ($oid1,$oid2,$oid3)) {
    ($bindings) = $session->decode_get_response ($session->{pdu_buffer});
    while ($bindings ne '') {
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$name=pretty_print ($value);
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$status=pretty_print ($value);
	($binding,$bindings) = &decode_sequence ($bindings);
	($oid,$value) = &decode_by_template ($binding, "%O%@");
	$maxspeed=(pretty_print ($value)/8);
	
	if ($status=="1") {
	  $file = $path.$host.".".$i.".log";
	@temp=split(/\n/,$file);
	$file=@temp[0].@temp[1];
	#print $file,"\n"; 
	open(INFO, $file);
	  @lines = <INFO>;
	  @elements=split(/ /,@lines[1]);
	  $curtot=@elements[1]+@elements[2];
	  $percentage=($curtot/$maxspeed)*100;
	  if ($percentage>$redline){
	    $graphic="<img src = red.gif>";
	  } elsif ($percentage>$yellowline) {
	    $graphic="<img src = yellow.gif>";
	  } else {
	    $graphic="<img src = green.gif>";
	  }
@outhead[$a]=$name;
@outvalue[$a]=$graphic;
$a++;
  }} 
} else {
    die "No response from agent on $host";
}
	
}
print $#outhead+1,">Utilisation statistics for ",$sysname," </TD></tr>";
for ($x=0; $x <= $#outhead; $x++) {
print "<td>",@outhead[$x],"</td>\n";
}
print "<tr>\n";
for ($x=0; $x <= $#outvalue; $x++) {
print "<td>",@outvalue[$x],"</td>\n";
}
@outhead=();
@outvalue=();
print <<"TEXT";
</tr>
</table><br>
</left></div>
TEXT
     
}
print "</body></html>";
