#!/usr/bin/perl

use Test::More tests => 3 + 2 + 5 + 2;

use DBI;
use strict;
use warnings;

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

##

{
  my $sth = $dbh->prepare(q{INSERT INTO regano.bailiwicks (domain_tail) VALUES (?)});
  $sth->{PrintError} = 0;
  foreach my $bogus_item ('test', '.test', 'test.') {
    $dbh->begin_work;
    eval { $sth->execute($bogus_item) };
    like($@, qr/violates check constraint/,
	 qq{Insert bogus '$bogus_item' bailiwick});
    $dbh->rollback;
  }
}

$dbh->do(q{INSERT INTO regano.bailiwicks (domain_tail) VALUES ('.test.')})
  if ($dbh->selectrow_array(q{SELECT COUNT(*) FROM regano.bailiwicks
				WHERE domain_tail = '.test.'}) == 0);
pass(q{Add '.test.' bailiwick});
eval {
  local $dbh->{PrintError};
  $dbh->do(q{INSERT INTO regano.bailiwicks (domain_tail) VALUES ('.test.')})
};
like($@, qr/duplicate key value violates unique constraint/,
     q{Verify unique '.test.' bailiwick});

{
  my $sth = $dbh->prepare(q{INSERT INTO regano.reserved_domains (domain_name, reason)
				VALUES (?, 'bogus')});
  $sth->{PrintError} = 0;
  foreach my $bogus_item ('example.test', 'example.test.',
			  '.example', '.example.', 'EXAMPLE') {
    $dbh->begin_work;
    eval { $sth->execute($bogus_item) };
    like($@, qr/violates check constraint/,
	 qq{Insert bogus '$bogus_item' reserved domain});
    $dbh->rollback;
  }
}

$dbh->do(q{INSERT INTO regano.reserved_domains (domain_name, reason)
		VALUES ('example', 'Reserved for testing purposes')})
  if ($dbh->selectrow_array(q{SELECT COUNT(*) FROM regano.reserved_domains
				WHERE domain_name = 'example'}) == 0);
pass(q{Reserve 'example' domain});
eval {
  local $dbh->{PrintError};
  $dbh->do(q{INSERT INTO regano.reserved_domains (domain_name, reason)
		VALUES ('example', 'bogus')})
};
like($@, qr/duplicate key value violates unique constraint/,
     q{Verify unique 'example' reserved domain});

##

$dbh->disconnect;

__END__
