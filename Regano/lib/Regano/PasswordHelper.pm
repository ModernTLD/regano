package Regano::PasswordHelper;

use Crypt::Random qw(makerandom_octet);
use Digest::SHA qw(hmac_sha384_base64);
use MIME::Base64 qw(encode_base64);

=head1 NAME

Regano::PasswordHelper - Centralized password digest handling

=head1 DESCRIPTION

Functions related to password digest handling needed in more than one place
in the Catalyst app.

=head1 FUNCTIONS

=head2 make_salt length

Generate a random salt by base64 encoding some random bytes.

=cut

sub make_salt ($) {
  $_[0] += 3 - $_[0] % 3 if $_[0] % 3; # round up to next multiple of 3
  my $salt = encode_base64(makerandom_octet( Length => $_[0], Strength => 0 ));
  chomp $salt;
  return $salt;
}

=head2 hash_password type, salt, password

Calculate a digest of password using salt according to type.

Types specify both what digest algorithm to use and how to encode the
output of the digest alogrithm as text.  The general form is
"hash/encoding".  If the specified hash is a plain digest, the salt is both
prepended and appended to the password as in "saltpasswordsalt".  If the
specified hash is a HMAC function, the salt is used as the HMAC key.

=cut

my %HASH_TYPES = (
    'hmac_sha384/base64' => sub {
	hmac_sha384_base64($_[1], $_[0])
    },
);

sub hash_password ($$$) {
    my ( $type, $salt, $password ) = @_;

    if (defined($HASH_TYPES{$type})) {
	return $HASH_TYPES{$type}($salt, $password);
    }

    die 'Composed digest/encoding not implemented';
}

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
