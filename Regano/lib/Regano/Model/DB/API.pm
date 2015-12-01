package Regano::Model::DB::API;
use Moose;
use namespace::autoclean;

extends 'Regano::Model::DB';

=head1 NAME

Regano::Model::DB::API - Catalyst Model

=head1 DESCRIPTION

Database stored procedure API bridge

=encoding utf8

=head1 METHODS

See db_api.sql for details.

=cut

my %METHODS = (
    'domain_status' => [ value => 'status', 'name' ],
    'domain_reservation_reason' => [ value => 'reason', 'name' ],

    'user_register' => [ nothing => undef,
			 'username', ['xdigest', 'xsalt', 'digest'],
			 'name', 'email' ],
    'user_get_salt_info' => [ row => ['xdigest', 'xsalt'], 'username' ],
    'user_login' => [ value => 'dbsession',
		      'username', ['xdigest', 'xsalt', 'digest'] ],
    'user_change_password' => [ value => 'success',
				'dbsession',
				['xdigest_old', 'xsalt_old', 'digest_old'],
				['xdigest_new', 'xsalt_new', 'digest_new'] ],

    'session_logout' => [ nothing => undef, 'dbsession' ],
    'session_check' => [ value => 'username', 'dbsession' ],

    'user_info' => [ row => ['id', 'username', 'contact_id', 'registered'],
		     'dbsession' ],
    'contact_primary_id' => [ value => 'contact_id', 'dbsession' ],
    'user_set_primary_contact' => [ nothing => undef,
				    'dbsession', 'contact_id' ],

    'contact_list' => [ table => ['id', 'name', 'email', 'email_verified'],
			'dbsession' ],
    'contact_add' => [ value => 'contact_id', 'dbsession', 'name', 'email' ],
    'contact_update_name' => [ nothing => undef,
			       'dbsession', 'contact_id', 'name' ],
    'contact_update_email' => [ nothing => undef,
				'dbsession', 'contact_id', 'email' ],
    'contact_verify_begin' => [ nothing => undef,
				'dbsession', 'contact_id' ],
    'contact_verify_complete' => [ value => 'success', 'verify', 'key' ],

    'domain_register' => [ value => 'status', 'dbsession', 'name' ],
);

sub map_args {
  join ',',
    map { ref($_) eq 'ARRAY' ? ('ROW('.map_args(@$_).')') : '?' } @_;
}

foreach my $method (keys %METHODS) {
  my ($retmode, $cols, @args) = @{$METHODS{$method}};
  my $spcall = join('',
		    'regano_api.', $method, '(', map_args(@args), ')');
  my $query;

  if ($retmode eq 'nothing') {
    $query = "SELECT $spcall"
  } elsif ($retmode eq 'value') {
    $query = "SELECT $spcall AS $cols"
  } elsif ($retmode eq 'row' or $retmode eq 'table') {
    $query = "SELECT ".join(',', @$cols)." FROM $spcall"
  } else {
    die "bad retmode"
  }

  if ($retmode eq 'nothing') {
    no strict 'refs';

    *{$method} = sub {
      my $self = shift;
      my $dbh = $self->dbh;
      my $sth = $dbh->prepare_cached($query);
      $sth->execute(@_);
      1 while $sth->fetch;
    };
  } elsif ($retmode eq 'value') {
    no strict 'refs';

    *{$method} = sub {
      my $self = shift;
      my $dbh = $self->dbh;
      my $sth = $dbh->prepare_cached($query);
      $sth->execute(@_);
      my ($value) = $sth->fetchrow_array;
      1 while $sth->fetch;
      return $value;
    };
  } elsif ($retmode eq 'row') {
    no strict 'refs';

    *{$method} = sub {
      my $self = shift;
      my $dbh = $self->dbh;
      my $sth = $dbh->prepare_cached($query);
      $sth->execute(@_);
      my $row = $sth->fetchrow_hashref('NAME_lc');
      1 while $sth->fetch;
      return $row;
    };
  } elsif ($retmode eq 'table') {
    no strict 'refs';

    *{$method} = sub {
      my $self = shift;
      my $dbh = $self->dbh;
      my $sth = $dbh->prepare_cached($query);
      $sth->execute(@_);
      my (@rows, $values);
      push @rows, $values while $values = $sth->fetchrow_hashref('NAME_lc');
      return [@rows];
    };
  }
}

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
