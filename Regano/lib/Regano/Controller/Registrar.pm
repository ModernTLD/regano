package Regano::Controller::Registrar;
use Moose;
use namespace::autoclean;

BEGIN { require Regano::PasswordHelper; }

BEGIN { extends 'Catalyst::Controller'; }

has 'AuthFrontendDigest' => ( is => 'ro', isa => 'Str' );
has 'AuthFrontendSaltLength' => ( is => 'ro', isa => 'Int' );

__PACKAGE__->config(
    AuthFrontendDigest => 'hmac_sha384/base64',
    AuthFrontendSaltLength => 6
);

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

    $c->response->header('Cache-Control'
			 => 'private, no-cache, no-store, must-revalidate');
    $c->response->header('Pragma' => 'no-cache');

    1;
}

=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    if (defined($c->stash->{session})) {
	# return account summary page
	my $dbsession = $c->session->{dbsession};
	$c->stash( template => 'registrar/overview.tt',
		   user_info => $c->model('DB::API')->user_info($dbsession),
		   contacts => $c->model('DB::API')->contact_list($dbsession),
		   domains => $c->model('DB::API')->domain_list($dbsession),
		   pending_domain =>
			$c->model('DB::API')->domain_check_pending($dbsession),
		   status => $c->session->{messages} );
	delete $c->session->{messages};
    } else {
	# return login page
	$c->stash( template => 'registrar/login.tt' );
	my $status_cookie = $c->request->cookie('acct_status');
	if (defined $status_cookie) {
	    $c->stash( acct => { status => $status_cookie->value,
				 name => $c->request->cookie('acct_name')->value } );
	    $c->log->debug('Got a status cookie: '.$status_cookie->value);
	    $c->response->cookies->{acct_status} = { value => '', expires => '-1d' };
	    $c->response->cookies->{acct_name}   = { value => '', expires => '-1d' };
	}
    }
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
    unless (defined $type) {
	$c->log->error('Login attempt with empty DB.');
	$c->response->redirect($c->uri_for_action('/registrar/index'));
	return 1;
    }
    my $digest = Regano::PasswordHelper::hash_password($type, $salt, $password);
    my $dbsession = $c->model('DB::API')->user_login($username, $type, $salt, $digest);

    if (defined($dbsession)) {
	$c->session( dbsession => $dbsession );
    } else {
	$c->response->cookies->{acct_status} = { value => 'login_incorrect' };
	$c->response->cookies->{acct_name}   = { value => $username };
    }

    $c->log->info('Login for user ['.$username.'] '.
		  (defined($dbsession) ? 'succeeded.' : 'failed.'));

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 create_account

Create a new account.

=cut

sub create_account :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $username = $c->request->params->{username};
    my $password = $c->request->params->{password1};
    my $password_mismatch = $password ne $c->request->params->{password2};
    my $contact_name = $c->request->params->{name};
    my $contact_email = $c->request->params->{email};
    my $type = $self->AuthFrontendDigest;
    my $salt = Regano::PasswordHelper::make_salt($self->AuthFrontendSaltLength);
    my $digest = Regano::PasswordHelper::hash_password($type, $salt, $password);

    $c->response->cookies->{acct_name} = { value => $username };
    if ($password_mismatch) {
	$c->response->cookies->{acct_status} = { value => 'password_mismatch' };
    } else {
	$c->log->info('Creating account for user ['.$username.'] '.
		      'with contact name ['.$contact_name.'] '.
		      'and email ['.$contact_email.'].'.
		      ' (auth '.$type.'; salt '.$salt.')');

	eval {
	    $c->model('DB::API')->user_register($username,
						$type, $salt, $digest,
						$contact_name, $contact_email)
	};
	if ($@ =~ m/violates unique constraint.*users_username/) {
	    $c->response->cookies->{acct_status} = { value => 'username_exists' };
	} elsif ($@) {
	    $c->response->cookies->{acct_status} = { value => 'db_error' };
	} else {
	    $c->response->cookies->{acct_status} = { value => 'account_created' };
	}
    }

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
