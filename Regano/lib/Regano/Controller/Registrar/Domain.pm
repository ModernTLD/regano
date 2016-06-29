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
	    and $c->request->method eq 'POST'
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

    my @messages = ();
    my $is_modified = 0;
    my $is_published = 0;

    my $params = $c->request->params;
    my $action = $params->{action};
    my $domain_name = $params->{domain_name};
    my @zone_keys = sort grep m/^zone_.*_seq_no$/, keys %{$params};

    my $dbsession = $c->session->{dbsession};
    my $domain_info = $c->model('DB')->domain_info($domain_name);
    my $user_info = $c->model('DB::API')->user_info($dbsession);

    unless ($domain_info->{owner_id} == $user_info->{id}
	    && !(defined $action && $action =~ m/^cancel/i)) {
	$c->response->redirect($c->uri_for_action('/registrar/index'));
	return;
    }

    my @zone_records;
    if (scalar @zone_keys == 0
	|| (defined($action) && $action =~ m/^reload/i)) {
	# load @zone_records from database
	my ($records, $zone_info) =
	    $c->model('DB::Zone')->records_for_domain($domain_name);
	@zone_records = @$records;
    } else {
	# load @zone_records from params

	$is_modified = 1;

	if (exists $params->{zone_r0_ttl}) {
	    # an SOA record exists
	    $zone_records[0] =
	    { ttl => $params->{zone_r0_ttl}, type => 'SOA', seq_no => 0,
	      data => { mbox => $params->{zone_r0_data_SOA_mbox},
			refresh => $params->{zone_r0_data_SOA_refresh},
			retry => $params->{zone_r0_data_SOA_retry},
			expire => $params->{zone_r0_data_SOA_expire},
			minimum => $params->{zone_r0_data_SOA_minimum} } };

	}
	my $seq_no = 1;
	our ($a, $b);
	foreach my $rs (map { m/^(zone_r\d+_)/; $1 }
			sort { $params->{$a} <=> $params->{$b}
			       || $params->{$a} cmp $params->{$b} }
			@zone_keys) {
	    my $type = $params->{$rs.'type'};
	    $zone_records[$seq_no] = { seq_no => $seq_no,
				       name =>   $params->{$rs.'name'},
				       ttl =>    $params->{$rs.'ttl'},
				       type =>   $type };
	    if (($type eq 'CNAME')||($type eq 'DNAME')
		||($type eq 'NS') ||($type eq 'PTR')) {
		$zone_records[$seq_no]->{data} =
		{ name =>         $params->{$rs.'data'} }
	    } elsif (($type eq 'SPF')||($type eq 'TXT')) {
		$zone_records[$seq_no]->{data} =
		{ text =>         $params->{$rs.'data'} }
	    } elsif ($type eq 'A') {
		$zone_records[$seq_no]->{data} =
		{ address =>      $params->{$rs.'data'} }
	    } elsif ($type eq 'AAAA') {
		$zone_records[$seq_no]->{data} =
		{ address =>      $params->{$rs.'data'} }
	    } elsif ($type eq 'DS') {
		$zone_records[$seq_no]->{data} =
		{ key_tag =>      $params->{$rs.'data_DS_key_tag'},
		  algorithm =>    $params->{$rs.'data_DS_algorithm'},
		  digest_type =>  $params->{$rs.'data_DS_digest_type'},
		  digest =>       $params->{$rs.'data_DS_digest'} }
	    } elsif ($type eq 'MX') {
		$zone_records[$seq_no]->{data} =
		{ preference =>   $params->{$rs.'data_MX_preference'},
		  exchange =>     $params->{$rs.'data_MX_exchange'} }
	    } elsif ($type eq 'SRV') {
		$zone_records[$seq_no]->{data} =
		{ priority =>     $params->{$rs.'data_SRV_priority'},
		  weight =>       $params->{$rs.'data_SRV_weight'},
		  port =>         $params->{$rs.'data_SRV_port'},
		  target =>       $params->{$rs.'data_SRV_target'} }
	    } else {
		delete $zone_records[$seq_no]; $seq_no--;
	    }
	    $seq_no++;
	}
    }
    shift @zone_records unless defined $zone_records[0];

    if (defined($action)) {
	if ($action =~ m/^insert.record/i) {
	    my $seq_no = $params->{ins_record_seq_no};
	    my $type = $params->{ins_record_type};
	    $seq_no = 1 unless 0+$seq_no;
	    $type = 'A' unless defined $type;
	    $seq_no = 1 if $seq_no < 1;
	    $seq_no = 0 if $type eq 'SOA';
	    my $pos = 0;
	    $pos++ while (defined $zone_records[$pos]
			  && $zone_records[$pos]{seq_no} < $seq_no);
	    splice(@zone_records, $pos, 0,
		   { seq_no => $seq_no, type => $type,
		     name => '@',	ttl => '',
		     data => { address => '',
			       name => '',
			       text => '',
			       # DS
			       key_tag => '',
			       algorithm => '',
			       digest_type => '',
			       digest  => '',
			       # MX
			       preference => '',
			       exchange => '',
			       # SRV
			       priority => '',
			       weight => '',
			       port => '',
			       target => '',
			       # SOA
			       mbox => '',
			       refresh => '',
			       retry => '',
			       expire => '',
			       minimum => '',
		     } });
	    $seq_no = 1;
	    $seq_no = 0 if $zone_records[0]{type} eq 'SOA';
	    $_->{seq_no} = $seq_no++ foreach @zone_records;
	    $is_modified = 1;
	} elsif ($action =~ m/^delete.record/i
		 && defined $params->{del_record_seq_no}
		 && $params->{del_record_seq_no} =~ m/^\d+$/) {
	    my $seq_no = $params->{del_record_seq_no};
	    my $pos = 0;
	    $pos++ while (defined $zone_records[$pos]
			  && $zone_records[$pos]{seq_no} < $seq_no);
	    splice(@zone_records, $pos, 1)
		if $zone_records[$pos]{seq_no} == $seq_no;
	    $seq_no = 1;
	    $seq_no = 0 if $zone_records[0]{type} eq 'SOA';
	    $_->{seq_no} = $seq_no++ foreach @zone_records;
	    $is_modified = 1;
	} elsif ($action =~ m/^publish/i) {
	    my $api = $c->model('DB::API');
	    my $seq_no = 0;
	    eval {
		$api->dbh->begin_work;
		$api->zone_clear($dbsession, $domain_name);
		foreach my $rec (@zone_records) {
		    $seq_no = $rec->{seq_no};
		    my $type = $rec->{type};
		    my $ttl = $rec->{ttl};
		    $ttl = undef unless $ttl;
		    if (($type eq 'CNAME')||($type eq 'DNAME')
			||($type eq 'NS') ||($type eq 'PTR')) {
			$api->zone_add_name($dbsession, $domain_name, $ttl,
					    $rec->{name}, $type, $rec->{data}{name});
		    } elsif (($type eq 'SPF')||($type eq 'TXT')) {
			$api->zone_add_text($dbsession, $domain_name, $ttl,
					    $rec->{name}, $type, $rec->{data}{text});
		    } elsif ($type eq 'A') {
			$api->zone_add_A($dbsession, $domain_name, $ttl,
					 $rec->{name}, $rec->{data}{address});
		    } elsif ($type eq 'AAAA') {
			$api->zone_add_AAAA($dbsession, $domain_name, $ttl,
					    $rec->{name}, $rec->{data}{address});
		    } elsif ($type eq 'DS') {
			$api->zone_add_DS($dbsession, $domain_name, $ttl,
					  $rec->{name}, $rec->{data}{key_tag},
					  $rec->{data}{algorithm},
					  $rec->{data}{digest_type},
					  $rec->{data}{digest});
		    } elsif ($type eq 'MX') {
			$api->zone_add_MX($dbsession, $domain_name, $ttl,
					  $rec->{name}, $rec->{data}{preference},
					  $rec->{data}{exchange});
		    } elsif ($type eq 'SRV') {
			$api->zone_add_SRV($dbsession, $domain_name, $ttl,
					   $rec->{name}, $rec->{data}{priority},
					   $rec->{data}{weight},
					   $rec->{data}{port},
					   $rec->{data}{target});
		    } elsif ($type eq 'SOA') {
			$api->zone_add_SOA($dbsession, $domain_name, $ttl,
					   $rec->{data}{mbox},
					   $rec->{data}{refresh},
					   $rec->{data}{retry},
					   $rec->{data}{expire},
					   $rec->{data}{minimum});
		    } else {
			die "unknown DNS record type: $type"
		    }
		}
		$api->dbh->commit;
		$is_modified = 0;
		$is_published = 1;
	    };
	    if ($@) {
		$api->dbh->rollback;
		$@ =~ s~^DBD::Pg.*?ERROR:~~;
		$@ =~ s~at /.*?lib/Regano/Model.*$~~;
		push @messages, ['publish_error', $seq_no, $@];
	    }
	} elsif ($action =~ m/^renew/i) {
	    eval {
		$c->model('DB::API')->domain_renew($dbsession, $domain_name)
	    };
	    push @messages, ['dberr', $@] if $@;
	    $domain_info = $c->model('DB')->domain_info($domain_name);
	} elsif ($action =~ m/^release/i) {
	    eval {
		$c->model('DB::API')->domain_release($dbsession, $domain_name)
	    };
	    push @messages, ['dberr', $@] if $@;
	    $domain_info = $c->model('DB')->domain_info($domain_name);
	} elsif ($action =~ m/^update.ttl/i
		 && ($c->request->params->{default_ttl}
		     ne $domain_info->{default_ttl})) {
	    eval {
		$c->model('DB::API')
		    ->domain_set_default_ttl($dbsession,
					     $domain_name,
					     $c->request->params->{default_ttl});
	    };
	    push @messages, ['dberr', $@] if $@;
	    $domain_info = $c->model('DB')->domain_info($domain_name);
	}
    }

    push @messages, ['edit_in_progress'] if $is_modified;

    $c->stash( name => $domain_name,
	       domain => $domain_info,
	       records => \@zone_records,
	       user => $user_info,
	       status => \@messages );

    $c->response->redirect($c->uri_for_action('/registrar/index'))
	if $is_published;
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
