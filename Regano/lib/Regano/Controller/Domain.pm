package Regano::Controller::Domain;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Domain - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    my $sth = $c->model('DB')->dbh->prepare_cached
	(q[SELECT domain_tail FROM regano.bailiwicks]);
    $sth->execute;
    my (@bailiwicks, $row);
    push @bailiwicks, $row->[0] while $row = $sth->fetchrow_arrayref;
    $c->stash( bailiwicks => \@bailiwicks );

    my $domain = $c->request->params->{name} . $c->request->params->{tail};
    if ($domain) {
	my ($status, $reason);
	$status = $c->model('DB::API')->domain_status($domain);
	$reason = $c->model('DB::API')->domain_reservation_reason($domain)
	    if $status eq 'RESERVED';
	$c->stash( domain => { name => $domain,
			       status => $status,
			       reason => $reason,
		   } );
    }

    $c->stash( template => 'domain_info.tt' );
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
