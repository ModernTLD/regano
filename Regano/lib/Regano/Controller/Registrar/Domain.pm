package Regano::Controller::Registrar::Domain;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Registrar::Domain - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 auto

=cut

sub auto :Private {
    my ( $self, $c ) = @_;

    return 1
	if (defined $c->stash->{session}
	    and defined $c->request->params->{domain_name});

    $c->response->redirect($c->uri_for_action('/registrar/index'));
    return 0;
}

=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 manage

Display domain management page and handle updates.

=cut

sub manage :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    my $action = $c->request->params->{action};
    my $domain_name = $c->request->params->{domain_name};
    my $domain_info = $c->model('DB')->domain_info($domain_name);
    my $user_info = $c->model('DB::API')->user_info($dbsession);

    unless ($domain_info->{owner_id} == $user_info->{id}) {
	$c->response->redirect($c->uri_for_action('/registrar/index'));
	return;
    }

    $c->stash( name => $domain_name,
	       domain => $domain_info,
	       user => $user_info,
	       status => $c->session->{messages} );
    delete $c->session->{messages};

    if (defined $c->request->params->{default_ttl}
	and $c->request->params->{default_ttl} ne $domain_info->{default_ttl}) {
	eval {
	    $c->model('DB::API')->domain_set_default_ttl($dbsession,
							 $domain_name,
							 $c->request->params->{default_ttl});
	};
	$c->stash( domain => $c->model('DB')->domain_info($domain_name) );
    }

    if (defined($action)) {
	if ($action =~ m/^renew/i) {
	    eval {
		$c->model('DB::API')->domain_renew($dbsession, $domain_name)
	    };
	    $c->stash( domain => $c->model('DB')->domain_info($domain_name) );
	}
	if ($action =~ m/^release/i) {
	    eval {
		$c->model('DB::API')->domain_release($dbsession, $domain_name)
	    };
	    $c->stash( domain => $c->model('DB')->domain_info($domain_name) );
	}
    }
}

=head2 register

Register a domain.

=cut

sub register :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    my $domain_name = $c->request->params->{domain_name};
    my $domain_tail = $c->request->params->{domain_tail};

    eval {
	$c->model('DB::API')->domain_register($dbsession,
					      $domain_name.$domain_tail)
    };

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 renew

Renew a domain.

=cut

sub renew :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    my $domain_name = $c->request->params->{domain_name};

    eval {
	$c->model('DB::API')->domain_renew($dbsession, $domain_name)
    };

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 release

Release a domain.

=cut

sub release :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    my $domain_name = $c->request->params->{domain_name};

    eval {
	$c->model('DB::API')->domain_release($dbsession, $domain_name)
    };

    $c->response->redirect($c->uri_for_action('/registrar/index'));
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
