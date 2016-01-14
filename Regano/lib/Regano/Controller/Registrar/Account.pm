package Regano::Controller::Registrar::Account;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

Regano::Controller::Registrar::Account - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 auto

=cut

sub auto :Private {
    my ( $self, $c ) = @_;

    return 1 if defined $c->stash->{session};

    $c->response->redirect($c->uri_for_action('/registrar/index'));
    return 0;
}

=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->response->redirect($c->uri_for_action('/registrar/index'));
}

=head2 contacts

Display contacts edit page.

=cut

sub contacts :Local :Args(0) {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    $c->stash( template => 'registrar/account/contacts.tt',
	       user_info => $c->model('DB::API')->user_info($dbsession),
	       contacts => $c->model('DB::API')->contact_list($dbsession),
	       status => $c->session->{messages} );
    delete $c->session->{messages};
}

=head2 contacts_edit

Store changes made to contact records.

=cut

sub contacts_edit :Local :Args(0) POST {
    my ( $self, $c ) = @_;

    my $dbsession = $c->session->{dbsession};
    my $user_info = $c->model('DB::API')->user_info($dbsession);
    my $params = $c->request->params;
    my %contacts = map {$_->{id} => $_}
			    @{$c->model('DB::API')->contact_list($dbsession)};
    my @items = sort grep m/^contact/, keys %{$params};
    my $set_primary_id = $params->{set_primary_id};

    if ($params->{set_primary_id} != $user_info->{contact_id}) {
	eval {
	    $c->model('DB::API')->user_set_primary_contact($dbsession,
							   $set_primary_id)
	};
	if ($@ =~ m/verified email address/) {
	    push @{$c->session->{messages}}, ['verify_primary',$set_primary_id];
	} elsif ($@) {
	    push @{$c->session->{messages}}, ['dberr_primary',$set_primary_id];
	} else {
	    push @{$c->session->{messages}}, ['set_primary',$set_primary_id];
	}
    }

    foreach my $item (@items) {
	my ( $id, $field ) = $item =~ m/^contact_(\d+)_(.*)$/;
	if ($field eq 'name') {
	    if ($params->{$item} ne $contacts{$id}{name}) {
		eval {
		    $c->model('DB::API')->contact_update_name($dbsession, $id,
							      $params->{$item})
		};
		if ($@) {
		    push @{$c->session->{messages}}, ['dberr_name', $id,
						      $params->{$item}];
		} else {
		    push @{$c->session->{messages}}, ['update_name', $id,
						      $params->{$item}];
		    $contacts{$id}{name} = $params->{$item};
		}
	    }
	} elsif ($field eq 'email') {
	    if ($params->{$item} ne $contacts{$id}{email}) {
		eval {
		    $c->model('DB::API')->contact_update_email($dbsession, $id,
							       $params->{$item})
		};
		if ($@ =~ m/for primary contact.*may not be changed/) {
		    push @{$c->session->{messages}}, ['verify_primary_email'];
		} elsif ($@) {
		    push @{$c->session->{messages}}, ['dberr_email', $id,
						      $params->{$item}];
		} else {
		    push @{$c->session->{messages}}, ['update_email', $id,
						      $params->{$item}];
		    $contacts{$id}{email} = $params->{$item};
		}
	    }
	} elsif ($field eq 'email_verify') {
	    # This can be done in the same loop because @items is sorted,
	    # and "email_verify" sorts after "email".  The verification
	    # will be done using the updated address if both are requested.
	    eval {
		$c->model('DB::API')->contact_verify_begin($dbsession, $id)
	    };
	    if ($@) {
		push @{$c->session->{messages}}, ['dberr_email_verify', $id,
						  $contacts{$id}{email}];
	    } else {
		push @{$c->session->{messages}}, ['verify_email', $id,
						  $contacts{$id}{email}];
	    }
	} elsif ($field eq 'remove') {
	    eval {
		$c->model('DB::API')->contact_remove($dbsession, $id)
	    };
	    if ($@) {
		push @{$c->session->{messages}}, ['dberr_remove', $id];
	    } else {
		push @{$c->session->{messages}}, ['remove_contact', $id];
	    }
	}
    }

    if ($params->{new_contact_name} =~ m/./
	&& $params->{new_contact_email} =~ m/./) {
	my $new_contact_id;
	eval {
	    $new_contact_id =
		$c->model('DB::API')->contact_add($dbsession,
						  $params->{new_contact_name},
						  $params->{new_contact_email})
	};
	if ($@) {
	    push @{$c->session->{messages}}, ['dberr_add'];
	} else {
	    push @{$c->session->{messages}}, ['add_contact', $new_contact_id];
	}
    } elsif ($params->{new_contact_name} =~ m/./
	     || $params->{new_contact_email} =~ m/./) {
	push @{$c->session->{messages}}, ['add_need_fields'];
    }

    $c->response->redirect($c->uri_for_action('/registrar/account/contacts'));
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
