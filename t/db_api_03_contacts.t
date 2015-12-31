#!/usr/bin/perl

use Test::More tests => 2 + 2 + 2 + 2 + 2 + 1 + 2 + 1 + 1;

use DBI;
use strict;
use warnings;

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

##

my ($TRUE, $FALSE) = $dbh->selectrow_array(q{SELECT TRUE, FALSE});

my %SESSIONS;
{
  my $sth = $dbh->prepare
    (q{WITH open_sessions AS
	 (SELECT s.*, dense_rank() OVER (PARTITION BY s.user_id
					 ORDER BY s.activity DESC)
	      FROM regano.sessions AS s)
	SELECT s.id, u.username, regano_api.session_check(s.id)
	    FROM open_sessions AS s JOIN regano.users AS u
		ON s.user_id = u.id
	    WHERE dense_rank = 1});
  $sth->execute;
  my ($id, $username, $check);
  $sth->bind_columns(\($id, $username, $check));
  while ($sth->fetch) {
    $SESSIONS{$username} = $id if $check;
  }
}

BAIL_OUT('No sessions in DB') unless scalar keys %SESSIONS;

##

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

{
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
  $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test1p1});
  pass(q{Change primary contact for 'test1'});
  $dbh->selectrow_array($set_primary_st, {}, $SESSIONS{test1}, $contacts{test1});

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
  pass(qq{Change email address back for contact $contacts{test1p1}});
}

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
}

##

$dbh->disconnect;

__END__
