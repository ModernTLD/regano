package Regano::Controller::Registrar;
use Moose;
use namespace::autoclean;

BEGIN { require Regano::PasswordHelper; }

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Registrar - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut

=head2 auto

=cut

sub auto :Private {
    my ( $self, $c ) = @_;
    my $expires = $c->session_expires;

    if (defined $expires && $expires != 0) {	# a frontend session exists
	my $username =
	    $c->model('DB::API')->session_check($c->session->{dbsession});
	if (defined($username)) {	# a backend session exists
	    $c->stash( session => { user => $username } );
	} else {
	    $c->delete_session('Invalid session');
	}
    }

    1;
}

=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    #$c->response->body('Matched Regano::Controller::Registrar in Registrar.');
    $c->stash( template => 'registrar/login.tt' );
}

=head2 login

Verify username and password, creating a session if successful.

=cut

sub login :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $username = $c->request->params->{username};
    my $password = $c->request->params->{password};
    my ( $type, $salt ) =
	@{$c->model('DB::API')->user_get_salt_info($username)}{'xdigest', 'xsalt'};
    my $digest = Regano::PasswordHelper::hash_password($type, $salt, $password);
    my $dbsession = $c->model('DB::API')->user_login($username, $type, $salt, $digest);

    $c->session( dbsession => $dbsession ) if (defined($dbsession));

    $c->log->info('Login for user ['.$username.'] '.
		  (defined($dbsession) ? 'succeeded.' : 'failed.'));

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 logout

End a session.

=cut

sub logout :Local :Args(0) {
    my ( $self, $c ) = @_;

    if (defined($c->stash->{session})) {
	$c->model('DB::API')->session_logout($c->session->{dbsession})
    }
    $c->delete_session('Logout');
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
