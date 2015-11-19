#!perl -w

use Test::More tests => 5;

use DBI;
use strict;
use warnings;

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

my ($TRUE, $FALSE) = $dbh->selectrow_array(q{SELECT TRUE, FALSE});

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

subtest 'User accounts (registration, login, passwords)' => sub {
  plan tests => 2 + 3*3 + 7;

  my ($digest, $salt, $result, $newsalt);
  my $reg_st = $dbh->prepare(q{SELECT regano_api.user_register(?, ROW(?,?,?), ?, ?)});
  my $chk_st = $dbh->prepare(q{SELECT COUNT(*) FROM regano.users WHERE username = ?});
  my $getsalt_st = $dbh->prepare
    (q{SELECT xdigest, xsalt FROM regano_api.user_get_salt_info(?)});
  my $login_st = $dbh->prepare(q{SELECT regano_api.user_login(?, ROW('','',?))});
  my $password_change_st = $dbh->prepare
    (q{SELECT regano_api.user_change_password(?, ROW('','',?), ROW(?,?,?))});

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

  $password_change_st->execute('00000000-0000-0000-0000-000000000000',
			       undef, undef, undef, undef);
  ($result) = $password_change_st->fetchrow_array;
  is($result, $FALSE, q{Change password on bogus session});

  ($digest, $salt) = $dbh->selectrow_array($getsalt_st, {}, 'test1');
  $password_change_st->execute($SESSIONS{test1},
			      hmac_sha384_base64('bogus', $salt),
			      'bogus', 'bogus', 'bogus');
  ($result) = $password_change_st->fetchrow_array;
  is($result, $FALSE, q{Change password with incorrect old password});

  $newsalt = make_salt 6;
  BAIL_OUT "cannot happen" if $newsalt eq $salt;
  $password_change_st->execute($SESSIONS{test1},
			      hmac_sha384_base64('password', $salt),
			      'hmac_sha384/base64', $newsalt,
			      hmac_sha384_base64('hunter2', $newsalt));
  ($result) = $password_change_st->fetchrow_array;
  is($result, $TRUE, q{Change password for 'test1'});

  ($digest, $salt) = $dbh->selectrow_array($getsalt_st, {}, 'test1');
  is($salt, $newsalt, q{Update stored salt});

  my $session = $dbh->selectrow_array
    ($login_st, {}, 'test1', hmac_sha384_base64('hunter2', $salt));
  like($session, $UUID_REGEX, q{Login with new password succeeds});

  $newsalt = make_salt 6;
  BAIL_OUT "cannot happen" if $newsalt eq $salt;
  $password_change_st->execute($SESSIONS{test1},
			      hmac_sha384_base64('hunter2', $salt),
			      'hmac_sha384/base64', $newsalt,
			      hmac_sha384_base64('password', $newsalt));
  ($result) = $password_change_st->fetchrow_array;
  is($result, $TRUE, q{Change password for 'test1' back});

  $dbh->selectrow_array(q{SELECT regano_api.session_logout(?)}, {}, $session);
  pass(q{Logout extra session});
};

sub verify_contact ($$) {
  plan tests => 8;

  my ($session, $id) = @_;
  my ($result, $vid, $vkey);

  my $verify_begin_st = $dbh->prepare
    (q{SELECT regano_api.contact_verify_begin(?, ?)});
  my $verify_check_st = $dbh->prepare
    (q{SELECT COUNT(*) FROM regano.contact_verifications WHERE contact_id = ?});
  my $verify_get_st = $dbh->prepare
    (q{SELECT id, key FROM regano.contact_verifications WHERE contact_id = ?});
  my $verify_complete_st = $dbh->prepare
    (q{SELECT regano_api.contact_verify_complete(?, ?)});

  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 0, qq{No previous pending verifies for contact $id});

  $dbh->selectrow_array($verify_begin_st, {}, $session, $id);
  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 1, qq{Started verification process for contact $id});

  $dbh->selectrow_array($verify_begin_st, {}, $session, $id);
  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 1, qq{Restarted verification process for contact $id});

  ($vid, $vkey) = $dbh->selectrow_array($verify_get_st, {}, $id);
  ($result) = $dbh->selectrow_array($verify_complete_st, {},
				    '00000000-0000-0000-0000-000000000000',
				    '00000000-0000-0000-0000-000000000000');
  is($result, $FALSE, q{Fail verify with bogus uuid});
  ($result) = $dbh->selectrow_array($verify_complete_st, {}, $vid,
				    '00000000-0000-0000-0000-000000000000');
  is($result, $FALSE, q{Fail verify with bogus key});
  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 1, qq{Incomplete verification for contact $id remains});
  ($result) = $dbh->selectrow_array($verify_complete_st, {}, $vid, $vkey);
  is($result, $TRUE, qq{Complete verification for contact $id});
  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 0, qq{Completed verification for contact $id removed});
}

subtest 'User accounts (contacts)' => sub {
  plan tests => 2 + 2 + 3 + 3 + 3 + 2 + 2 + 1;

  my %contacts;
  my $contact_add_st = $dbh->prepare(q{SELECT regano_api.contact_add(?, ?, ?)});
  my $contact_get_st = $dbh->prepare
    (q{SELECT id FROM regano_api.contact_list(?) WHERE email = ?});
  my $contact_list_st = $dbh->prepare
    (q{SELECT name, email, email_verified FROM regano_api.contact_list(?) ORDER BY name});
  my $contact_update_email_st = $dbh->prepare
    (q{SELECT regano_api.contact_update_email(?, ?, ?)});
  my $contact_update_name_st = $dbh->prepare
    (q{SELECT regano_api.contact_update_name(?, ?, ?)});
  my $get_primary_st = $dbh->prepare(q{SELECT regano_api.contact_primary_id(?)});
  my $set_primary_st = $dbh->prepare
    (q{SELECT regano_api.user_set_primary_contact(?, ?)});

  ($contacts{test1}) = $dbh->selectrow_array($get_primary_st, {}, $SESSIONS{test1});
  like($contacts{test1}, qr/\d+/, q{Get primary contact id for 'test1'});
  ($contacts{test2}) = $dbh->selectrow_array($get_primary_st, {}, $SESSIONS{test2});
  like($contacts{test2}, qr/\d+/, q{Get primary contact id for 'test2'});

  ($contacts{test1p1}) = $dbh->selectrow_array($contact_get_st, {},
					       $SESSIONS{test1},
					       'spamtrap@example.com')
    || $dbh->selectrow_array($contact_add_st, {},
			     $SESSIONS{test1},
			     'Test User Public', 'spamtrap@example.com');
  like($contacts{test1p1}, qr/\d+/, q{Add contact for 'test1'});
  ($contacts{test1p2}) = $dbh->selectrow_array($contact_get_st, {},
					       $SESSIONS{test1},
					       'spamtrap2@example.com')
    || $dbh->selectrow_array($contact_add_st, {},
			     $SESSIONS{test1},
			     'Test User Public 2', 'spamtrap2@example.com');
  like($contacts{test1p2}, qr/\d+/, q{Add another contact for 'test1'});

  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array(q{SELECT regano_api.contact_verify_begin(?, ?)}, {},
			  $SESSIONS{test1}, $contacts{test2});
  };
  like($@, qr/not belonging to current user/,
       q{Check ownership of contact for verification});
  subtest q{Verify primary contact for 'test1'} => sub {
    verify_contact $SESSIONS{test1}, $contacts{test1};
  };
  subtest q{Verify a second contact for 'test1'} => sub {
    verify_contact $SESSIONS{test1}, $contacts{test1p1};
  };

  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test1p2});
  };
  like($@, qr/Only a verified email address may be set as primary contact/,
       q{Only a verified email address may be set as primary contact});
  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test2});
  };
  like($@, qr/not belonging to current user/,
       q{Check ownership of contact for primary contact});
  $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test1p1});
  pass(q{Change primary contact for 'test1'});
  $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test1});

  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array($contact_update_email_st, {},
			  $SESSIONS{test1}, $contacts{test2},
			  'bogus@example.com');
  };
  like($@, qr/not belonging to current user/,
      q{Check ownership of contact before changing email address});
  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array($contact_update_email_st, {},
			  $SESSIONS{test1}, $contacts{test1},
			  'bogus@example.com');
  };
  like($@, qr/Verified email address \(.*\) for primary contact/,
       q{Restrict changing verified primary email address});
  $dbh->selectrow_array($contact_update_email_st, {},
			$SESSIONS{test1}, $contacts{test1p1},
			'spamtrap1@example.com');
  pass(qq{Change email address for contact $contacts{test1p1}});

  eval {
    local $dbh->{PrintError};
    $dbh->selectrow_array($contact_update_name_st, {},
			 $SESSIONS{test1}, $contacts{test2}, 'bogus');
  };
  like($@, qr/not belonging to current user/,
      q{Check ownership of contact before changing name});
  $dbh->selectrow_array($contact_update_name_st, {},
			$SESSIONS{test1}, $contacts{test1}, 'Test User 1A');
  pass(qq{Change name for contact $contacts{test1}});

  is_deeply($dbh->selectall_arrayref($contact_list_st, {}, $SESSIONS{test1}),
	   [['Test User 1A', 'test1@example.com', $TRUE],
	    ['Test User Public', 'spamtrap1@example.com', $FALSE],
	    ['Test User Public 2', 'spamtrap2@example.com', $FALSE]],
	    q{Contact list for 'test1'});
  is_deeply($dbh->selectall_arrayref($contact_list_st, {}, $SESSIONS{test2}),
	   [['Test User 2', 'test2@example.com', $FALSE]],
	    q{Contact list for 'test2'});

  $dbh->selectrow_array($contact_update_email_st, {},
			$SESSIONS{test1}, $contacts{test1p1},
			'spamtrap@example.com');
  pass(qq{Change email address back for contact $contacts{test1p1}})
};

subtest 'Exploits' => sub {
  plan tests => 1;

  {
    #  exploit:	(1) create a contact with valid email address
    #		(2) request verification of email address
    #		(3) receive verification email with link
    #		(4) change contact email address
    #		(5) use link from (3) to "verify" address from (4)
    #  prevented by invalidating existing verification links when an
    #  address is changed

    my $verify_begin_st = $dbh->prepare
      (q{SELECT regano_api.contact_verify_begin(?, ?)});
    my $verify_get_st = $dbh->prepare
      (q{SELECT id, key FROM regano.contact_verifications WHERE contact_id = ?});
    my $verify_complete_st = $dbh->prepare
      (q{SELECT regano_api.contact_verify_complete(?, ?)});
    my $contact_add_st = $dbh->prepare(q{SELECT regano_api.contact_add(?, ?, ?)});
    my $contact_update_email_st = $dbh->prepare
      (q{SELECT regano_api.contact_update_email(?, ?, ?)});

    $dbh->begin_work;
    # (1)
    my $contact = $dbh->selectrow_array($contact_add_st, {},
					$SESSIONS{test2},
					'Bogus Contact', 'test2b@example.com');
    # (2)
    $dbh->selectrow_array($verify_begin_st, {}, $SESSIONS{test2}, $contact);

    # (3)
    my ($vid, $vkey) = $dbh->selectrow_array($verify_get_st, {}, $contact);

    # (4)
    $dbh->selectrow_array($contact_update_email_st, {},
			  $SESSIONS{test2}, $contact, 'bogus@example.com');

    # (5)
    my ($result) = $dbh->selectrow_array($verify_complete_st, {}, $vid, $vkey);
    is($result, $FALSE, q{Reject verification after changing address});

    $dbh->rollback;
  };
};

$dbh->disconnect;

__END__
