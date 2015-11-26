#!/usr/bin/perl

# Database intialization for Regano

#  Regano is free software.  You can redistribute it and/or modify
#  it under the same terms as Perl itself.

use DBI;
use strict;
use warnings;

my $dbh;

$dbh = DBI->connect('dbi:Pg:db=template1', undef, undef,
		    {AutoCommit => 1, RaiseError => 1})
  or die $DBI::errstr;

eval {
  local $dbh->{PrintError};
  print "ensure 'regano' user exists\n";
  $dbh->do(q[CREATE ROLE "regano" WITH LOGIN]);
};
eval {
  local $dbh->{PrintError};
  print "ensure 'regano-www' user exists\n";
  $dbh->do(q[CREATE ROLE "regano-www" WITH LOGIN]);
};

eval {
  local $dbh->{PrintError};
  $dbh->do(q[DROP DATABASE "regano"]);
  print "erase database 'regano'\n";
};
$dbh->do(q[CREATE DATABASE "regano" WITH OWNER = "regano"]);
print "create database 'regano'\n";

$dbh->disconnect;

foreach my $part (qw(types tables functions config api)) {
  system {'psql'} qw(psql -d regano -f), "db_${part}.sql"
}

__END__
