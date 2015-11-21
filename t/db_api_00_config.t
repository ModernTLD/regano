#!/usr/bin/perl

use Test::More;

use DBI;
use strict;
use warnings;

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

##

my %CONFIG_KEYS = ( 'auth/crypt' => ['number', 'text'],
		    'session/max_age' => ['interval'],
		    'session/max_idle' => ['interval'],
		    'verify/max_age' => ['interval'],
		    'domain/pend_term' => ['interval'],
		    'domain/term' => ['interval'],
		  );

plan tests => scalar keys %CONFIG_KEYS;
my $sth = $dbh->prepare(q{SELECT interval, number, text FROM regano.config_get(?)});
foreach my $key (keys %CONFIG_KEYS) {
  $sth->execute($key);
  my ($number, $text, $interval);
  $sth->bind_columns(\($interval, $number, $text));
  while ($sth->fetch) {
    my @values = ();
    push @values, 'interval' if defined $interval;
    push @values, 'number' if defined $number;
      push @values, 'text' if defined $text;
    is_deeply($CONFIG_KEYS{$key}, \@values, "config key '$key'");
  }
}

##

$dbh->disconnect;

__END__
