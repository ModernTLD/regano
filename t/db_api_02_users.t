#!/usr/bin/perl

use Test::More tests => 2 + 3*3 + 7;

use DBI;
use strict;
use warnings;

use Crypt::Random qw(makerandom_octet);
use Digest::SHA qw(hmac_sha384_base64);
use MIME::Base64 qw(encode_base64);

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

##

my $UUID_REGEX = qr/[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}/i;

sub make_salt ($) {
  $_[0] += 3 - $_[0] % 3 if $_[0] % 3; # round up to next multiple of 3
  my $salt = encode_base64(makerandom_octet( Length => $_[0], Strength => 0 ));
  chomp $salt;
  return $salt;
}

my ($TRUE, $FALSE) = $dbh->selectrow_array(q{SELECT TRUE, FALSE});

##

my %SESSIONS;
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
1 while $password_change_st->fetch;  # clean up bogus "rows" to keep DBI happy

$dbh->selectrow_array(q{SELECT regano_api.session_logout(?)}, {}, $session);
pass(q{Logout extra session});

##

$dbh->disconnect;

__END__
