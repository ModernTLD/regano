package Regano::Controller::Verify;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Verify - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 index

=cut

sub index :Path :Args(2) {
    my ( $self, $c, $vid, $key ) = @_;

    my $result = eval { $c->model('DB::API')->contact_verify_complete($vid, $key) };

    if ($@) {
	$c->response->redirect($c->uri_for_action('/registrar/index'));
    } else {
	$c->stash( verification_result => $result,
		   template => 'verify.tt' );
    }
}



=encoding utf8

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
