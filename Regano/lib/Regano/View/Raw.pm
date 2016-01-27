package Regano::View::Raw;
use Moose;
use namespace::autoclean;

extends 'Catalyst::View::TT';

__PACKAGE__->config(
    TEMPLATE_EXTENSION => '.tt',
    render_die => 1,
    CATALYST_VAR => 'regano',
);

=head1 NAME

Regano::View::Raw - TT View for Regano

=head1 DESCRIPTION

TT View for Regano.

=head1 SEE ALSO

L<Regano>

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
