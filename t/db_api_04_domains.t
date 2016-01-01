#!/usr/bin/perl

use Test::More tests => 4*2 + 2 + 4 + 8;

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
  plan tests => 4;

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

  ($vid, $vkey) = $dbh->selectrow_array($verify_get_st, {}, $id);
  ($result) = $dbh->selectrow_array($verify_complete_st, {}, $vid, $vkey);
  is($result, $TRUE, qq{Complete verification for contact $id});

  $result = $dbh->selectrow_array($verify_check_st, {}, $id);
  is($result, 0, qq{Completed verification for contact $id removed});
}

sub check_status ($$) {
  my ($domain, $status) = @_;
  my $domain_status_st = $dbh->prepare_cached
    (q{SELECT regano_api.domain_status(?)});
  my ($result) = $dbh->selectrow_array($domain_status_st, {}, $domain);
  is($result, $status, qq{Domain '$domain' is $status});
}

sub check_reason ($$) {
  my ($domain, $status) = @_;
  my $domain_reservation_reason_st = $dbh->prepare_cached
    (q{SELECT regano_api.domain_reservation_reason(?)});
  my ($result) = $dbh->selectrow_array($domain_reservation_reason_st, {}, $domain);
  if ($status eq 'RESERVED') {
    like($result, qr/.+/, qq{Domain '$domain' reserved: $result});
  } else {
    is($result, undef, qq{No reason for '$domain' to be reserved});
  }
}

sub check_status_and_reason ($$) {
  my ($domain, $status) = @_;
  check_status $domain, $status;
  check_reason $domain, $status;
}

{
  my $domain_status_st = $dbh->prepare_cached
    (q{SELECT regano_api.domain_status(?)});
  my $domain_register_st = $dbh->prepare
    (q{SELECT regano_api.domain_register(?, ?)});
  my $domain_release_st = $dbh->prepare
    (q{SELECT regano_api.domain_release(?, ?)});
  my $domain_renew_st = $dbh->prepare
    (q{SELECT regano_api.domain_renew(?, ?)});
  my $get_expiration_st = $dbh->prepare
    (q{SELECT expiration FROM regano.domains
	WHERE domain_name = ? AND domain_tail = '.test.'});
  my $age_expiration_st = $dbh->prepare
    (q{UPDATE regano.domains
	SET expiration = expiration - (regano.config_get('domain/grace_period')).interval
	WHERE domain_name = ? AND domain_tail = '.test.'});
  my $check_pending_st = $dbh->prepare
    (q{SELECT * FROM regano_api.domain_check_pending(?)});
  my $domain_list_st = $dbh->prepare
    (q{SELECT * FROM regano_api.domain_list(?)});

  my ($result, $expire1, $expire2);
  my ($registered, $now, $expires);

  # clean up after a previous test run
  $result = $dbh->selectrow_array($domain_status_st, {}, 'test.test.');
  if ($result ne 'AVAILABLE') {
    $dbh->do(q{DELETE FROM regano.domains WHERE domain_tail = '.test.'});
    $dbh->do(q{UPDATE regano.contacts SET email_verified = FALSE
		FROM regano.users WHERE users.username = 'test2'
			AND contacts.owner_id = users.id})
  }

  check_status_and_reason 'example.com.', 'ELSEWHERE';
  check_status_and_reason 'example.test.', 'RESERVED';
  check_status_and_reason 'test.example.', 'ELSEWHERE';
  check_status_and_reason 'test.test.', 'AVAILABLE';

  $dbh->begin_work;
  ($registered) = $dbh->selectrow_array(q{SELECT now()});
  $result = $dbh->selectrow_array($domain_register_st, {},
				  $SESSIONS{test1}, 'test.test.');
  $dbh->commit;
  is($result, 'REGISTERED', qq{Register domain 'test.test.'});

  $dbh->begin_work;
  ($now, $expires) = $dbh->selectrow_array
    (q{SELECT now(), now() + regano.config_get('domain/pend_term')});
  $result = $dbh->selectrow_array($domain_register_st, {},
				  $SESSIONS{test2}, 'test-pend.test.');
  $dbh->commit;
  is($result, 'PENDING', qq{Register pending domain 'test-pend.test.'});

  check_status 'test-pend.test.', 'PENDING';
  is_deeply($dbh->selectall_arrayref($check_pending_st, {}, $SESSIONS{test2}),
	    [['test-pend.test.', $now, $expires]],
	    q{Pending domain listed for 'test2'});
  subtest q{Verify primary contact for 'test2'} => sub {
    my $cid = $dbh->selectrow_array(q{SELECT regano_api.contact_primary_id(?)},
				    {}, $SESSIONS{test2});
    verify_contact $SESSIONS{test2}, $cid;
  };
  check_status 'test-pend.test.', 'REGISTERED';

  $expire1 = $dbh->selectrow_array($get_expiration_st, {}, 'test');
  $dbh->selectrow_array($domain_release_st, {},
			$SESSIONS{test1}, 'test.test.');
  $expire2 = $dbh->selectrow_array($get_expiration_st, {}, 'test');
  isnt($expire1, $expire2, qq{Release domain 'test.test.'});
  check_status 'test.test.', 'EXPIRED';

  $expire1 = $dbh->selectrow_array($get_expiration_st, {}, 'test');
  $dbh->begin_work;
  ($now, $expires) = $dbh->selectrow_array
    (q{SELECT now(), now() + regano.config_get('domain/term')});
  $dbh->selectrow_array($domain_renew_st, {},
			$SESSIONS{test1}, 'test.test.');
  $dbh->commit;
  $expire2 = $dbh->selectrow_array($get_expiration_st, {}, 'test');
  isnt($expire1, $expire2, qq{Renew domain 'test.test.'});
  check_status 'test.test.', 'REGISTERED';

  is_deeply($dbh->selectall_arrayref($domain_list_st, {}, $SESSIONS{test1}),
	    [['test.test.', $registered, $expires, $now]],
	    q{List domains for 'test1'});

  $expire1 = $dbh->selectrow_array($get_expiration_st, {}, 'test-pend');
  $dbh->selectrow_array($domain_release_st, {},
			$SESSIONS{test2}, 'test-pend.test.');
  $expire2 = $dbh->selectrow_array($get_expiration_st, {}, 'test-pend');
  isnt($expire1, $expire2, qq{Release domain 'test-pend.test.'});
  check_status 'test-pend.test.', 'EXPIRED';
  $age_expiration_st->execute('test-pend');
  check_status 'test-pend.test.', 'AVAILABLE';

  # clean up
  $dbh->do(q{UPDATE regano.contacts SET email_verified = FALSE
		FROM regano.users WHERE users.username = 'test2'
			AND contacts.owner_id = users.id});
}

##

$dbh->disconnect;

__END__
