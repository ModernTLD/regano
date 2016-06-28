package Regano::Model::DB;

use strict;
use warnings;
use parent 'Catalyst::Model::DBI';

__PACKAGE__->config(
  dsn           => 'dbi:Pg:db=regano',
  user          => '',
  password      => '',
  options       => { AutoCommit => 1, RaiseError => 1 },
);

=head1 NAME

Regano::Model::DB - DBI Model Class

=head1 SYNOPSIS

See L<Regano>

=head1 DESCRIPTION

This is the database glue module for Regano.

=head1 METHODS

=head2 bailiwick_tails

Get a reference to an array of known domain tails.

=cut

sub bailiwick_tails {
    my $self = shift;
    my $dbh = $self->dbh;
    my $sth = $dbh->prepare_cached
	(q[SELECT domain_tail FROM regano.bailiwicks]);
    $sth->execute;
    my (@bailiwicks, $tail);
    $sth->bind_columns(\$tail);
    push @bailiwicks, $tail while $sth->fetch;

    return \@bailiwicks;
}

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
