#!/logiciels/public/divers/bin/perl5

require 5;

require 'Party.pm';

Party::read_cmu_party_database('/etc/party.conf');
Party->find ('zeusmsmd5')->describe (STDERR);

1;
