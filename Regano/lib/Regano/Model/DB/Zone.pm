package Regano::Model::DB::Zone;
use Moose;
use namespace::autoclean;

extends 'Regano::Model::DB';

=head1 NAME

Regano::Model::DB::Zone - Catalyst Model

=head1 DESCRIPTION

Database bridge for DNS zone records

=encoding utf8

=head1 METHODS

=cut


=head2 records_for_domain

Return arrayref of hashes representing records for the named domain.

Each hash contains name/class/type/ttl, and a data key that holds a hash
with the fields and values for this record.

=cut

sub records_for_domain {
    my ( $self, $zone_name ) = @_;
    my @records = ();
    my %types = ();
    my $dbh = $self->dbh;

    my $get_domain_info_st = $dbh->prepare_cached
	(q{SELECT id, EXTRACT(EPOCH FROM default_ttl),
		    EXTRACT(EPOCH FROM date_trunc('second', last_update))
		FROM regano.domains
		WHERE lower(domain_name||domain_tail) = lower(?)});
    my $get_records_st = $dbh->prepare_cached
	(q{SELECT seq_no, name, class, type, EXTRACT(EPOCH FROM ttl),
		  data_name, data_text, data_RR_A, data_RR_AAAA,
		  (data_RR_SOA).*,
		  (data_RR_DS).*,
		  (data_RR_MX).*,
		  (data_RR_SRV).*
		FROM regano.domain_records
		WHERE domain_id = ?});

    my ( $domain_id, $default_ttl, $serial ) = $dbh->selectrow_array
	($get_domain_info_st, {}, $zone_name);

    return [] unless defined $domain_id;

    {
	$get_records_st->execute($domain_id);
	my ( $seq_no, $name, $class, $type, $ttl,
	     $data_name, $data_text, $data_A, $data_AAAA,
	     # SOA
	     $SOA_zone, $SOA_mbox, $SOA_refresh,
	     $SOA_retry, $SOA_expire, $SOA_minimum,
	     # DS
	     $DS_key_tag, $DS_algorithm, $DS_digest_type, $DS_digest,
	     # MX
	     $MX_preference, $MX_exchange,
	     # SRV
	     $SRV_priority, $SRV_weight, $SRV_port, $SRV_target );
	$get_records_st->bind_columns
	    (\ ($seq_no, $name, $class, $type, $ttl,
		$data_name, $data_text, $data_A, $data_AAAA,
		# SOA
		$SOA_zone, $SOA_mbox, $SOA_refresh,
		$SOA_retry, $SOA_expire, $SOA_minimum,
		# DS
		$DS_key_tag, $DS_algorithm, $DS_digest_type, $DS_digest,
		# MX
		$MX_preference, $MX_exchange,
		# SRV
		$SRV_priority, $SRV_weight, $SRV_port, $SRV_target));
	while ($get_records_st->fetch) {
	    $types{$type}++;
	    $records[$seq_no] = { name => $name,
				  class => $class,
				  type => $type,
				  ttl => defined($ttl) ? $ttl : $default_ttl };
	    if (($type eq 'CNAME')||($type eq 'DNAME')
		||($type eq 'NS') ||($type eq 'PTR')) {
		$records[$seq_no]->{data} = { name => $data_name }
	    } elsif (($type eq 'SPF')||($type eq 'TXT')) {
		$records[$seq_no]->{data} = { text => $data_text }
	    } elsif ($type eq 'A') {
		$records[$seq_no]->{data} = { address => $data_A }
	    } elsif ($type eq 'AAAA') {
		$records[$seq_no]->{data} = { address => $data_AAAA }
	    } elsif ($type eq 'DS') {
		$records[$seq_no]->{data} = { key_tag => $DS_key_tag,
					      algorithm => $DS_algorithm,
					      digest_type => $DS_digest_type,
					      digest => $DS_digest }
	    } elsif ($type eq 'MX') {
		$records[$seq_no]->{data} = { preference => $MX_preference,
					      exchange => $MX_exchange }
	    } elsif ($type eq 'SRV') {
		$records[$seq_no]->{data} = { priority => $SRV_priority,
					      weight => $SRV_weight,
					      port => $SRV_port,
					      target => $SRV_target }
	    } elsif ($type eq 'SOA') {
		$records[$seq_no]->{data} = { zone => $SOA_zone,
					      mbox => $SOA_mbox,
					      serial => $serial,
					      refresh => $SOA_refresh,
					      retry => $SOA_retry,
					      expire => $SOA_expire,
					      minimum => $SOA_minimum }
	    } else {
		die "unknown DNS record type"
	    }
	}
    }

    return \@records;
}

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
