package Regano::Model::DB;

use strict;
use warnings;
use parent 'Catalyst::Model::DBI';

__PACKAGE__->config(
  dsn           => 'dbi:Pg:db=regano',
  user          => '',
  password      => '',
  options       => {},
);

=head1 NAME

Regano::Model::DB - DBI Model Class

=head1 SYNOPSIS

See L<Regano>

=head1 DESCRIPTION

DBI Model Class.

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
