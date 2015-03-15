# Introduction #

SNMP\_Session.pm provides access to management instrumentation on remote SNMP agents.  It supports SNMPv1 and SNMPv2 (community-based, sometimes called "SNMPv2c"), using UDP over IPv4 or IPv6.

# Details #

This module differs from existing SNMP packages in that it is completely stand-alone, i.e. you don't need to have another SNMP package such as Net-SNMP. It is also written entirely in Perl, so you don't have to compile any C modules. It uses the Perl 5 Socket.pm module and should therefore be very portable, even to non-Unix systems.  The SNMP operations currently supported are `get`, `get-next`, `get-bulk` and `set`, as well as trap generation and reception.

**Note:** For the development of new scripts, I strongly recommend to use the higher-level programming interface provided by `SNMP_util.pm`. Its use is described in [README.SNMP\_util](http://code.google.com/p/snmp-session/source/browse/trunk/README.SNMP_util).

For an excellent example of the type of application this is useful for, see Tobias Oetiker's [mrtg](http://oss.oetiker.ch/mrtg/) (Multi Router Traffic Grapher) tool. Another application that uses this library is IOG (Input/Output Grapher).