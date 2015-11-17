#!perl -w

use Test::More tests => 3;

use DBI;
use strict;

use Crypt::Random qw(makerandom_octet);
use Digest::SHA qw(hmac_sha384_base64);
use MIME::Base64 qw(encode_base64);

my %CONFIG_KEYS = ( 'auth/crypt' => ['number', 'text'],
		    'session/max_age' => ['interval'],
		    'session/max_idle' => ['interval'],
		    'verify/max_age' => ['interval'],
		    'domain/pend_term' => ['interval'],
		    'domain/term' => ['interval'],
		  );

my $UUID_REGEX = qr/[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}/i;

my %SESSIONS; # session IDs

sub make_salt ($) {
  $_[0] += 3 - $_[0] % 3 if $_[0] % 3; # round up to next multiple of 3
  my $salt = encode_base64(makerandom_octet( Length => $_[0], Strength => 0 ));
  chomp $salt;
  return $salt;
}

##

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

subtest 'Verify configuration' => sub {
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
};

subtest 'Set parameters' => sub {
  plan tests => 3 + 2 + 5 + 2;

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
};

subtest 'User accounts' => sub {
  plan tests => 2 + 3*3;

  my ($digest, $salt);
  my $reg_st = $dbh->prepare(q{SELECT regano_api.user_register(?, ROW(?,?,?), ?, ?)});
  my $chk_st = $dbh->prepare(q{SELECT COUNT(*) FROM regano.users WHERE username = ?});
  my $getsalt_st = $dbh->prepare
    (q{SELECT xdigest, xsalt FROM regano_api.user_get_salt_info(?)});
  my $login_st = $dbh->prepare(q{SELECT regano_api.user_login(?, ROW('','',?))});

  $salt = make_salt 6;
  $reg_st->execute('test1',
		   'hmac_sha384/base64', $salt,
		   hmac_sha384_base64('password', $salt),
		   'Test User 1',
		   'test1@example.com')
    unless $dbh->selectrow_array($chk_st, {}, 'test1');
  pass(q{Register user 'test1'});

  $salt = make_salt 6;
  $reg_st->execute('test2',
		   'hmac_sha384/base64', $salt,
		   hmac_sha384_base64('password', $salt),
		   'Test User 2',
		   'test2@example.com')
    unless $dbh->selectrow_array($chk_st, {}, 'test2');
  pass(q{Register user 'test2'});

  foreach my $username ('bogus', 'test1', 'test2') {
    ($digest, $salt) = $dbh->selectrow_array($getsalt_st, {}, $username);
    is($digest, 'hmac_sha384/base64', qq{Verify '$username' digest type});
    like($salt, qr{[[:alnum:]+/]{8}}, qq{Verify '$username' salt});

    $SESSIONS{$username} = $dbh->selectrow_array
      ($login_st, {}, $username, hmac_sha384_base64('password', $salt));
    if ($username eq 'bogus') {
      is($SESSIONS{$username}, undef, q{Login for 'bogus' fails});
    } else {
      like($SESSIONS{$username}, $UUID_REGEX, qq{Login for '$username' succeeds});
    }
  }
};

$dbh->disconnect;

__END__
