package Regano::Controller::Zone;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Zone - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->response->body('Matched Regano::Controller::Zone in Zone.');
}

=head2 zone

Return DNS records for requested zone.

=cut

sub zone :Path :Args(1) {
    my ( $self, $c, $zone_name ) = @_;

    return $c->response->redirect($c->request->uri . '.')
	unless $zone_name =~ m/\.$/;

    my $type = $c->model('DB::API')->domain_status($zone_name);

    if ($type eq 'REGISTERED') {
	# return records for single domain
	$c->stash( template => 'zone/domain_html.tt',
		   zone => { name => $zone_name,
			     records => $c->model('DB::Zone')
				 ->records_for_domain($zone_name) } );
    } elsif ($type eq 'BAILIWICK') {
	# return bailiwick zone
	$c->response->body("Read $type zone $zone_name");
    } else {
	$c->response->status(404);
	$c->stash( template => 'zone/not_found.tt',
		   zone => { name => $zone_name } );
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