#!/usr/bin/perl

use Test::More tests => 8 + 2;

use DBI;
use strict;
use warnings;

my $dbh = DBI->connect('dbi:Pg:db=regano', undef, undef,
		       {AutoCommit => 1, RaiseError => 1})
  or BAIL_OUT $DBI::errstr;

##

my ($TRUE, $FALSE) = $dbh->selectrow_array(q{SELECT TRUE, FALSE});

my %SESSIONS;
{
  my $sth = $dbh->prepare
    (q{WITH open_sessions AS
	 (SELECT s.*, dense_rank() OVER (PARTITION BY s.user_id
					 ORDER BY s.activity DESC)
	      FROM regano.sessions AS s)
	SELECT s.id, u.username, regano_api.session_check(s.id)
	    FROM open_sessions AS s JOIN regano.users AS u
		ON s.user_id = u.id
	    WHERE dense_rank = 1});
  $sth->execute;
  my ($id, $username, $check);
  $sth->bind_columns(\($id, $username, $check));
  while ($sth->fetch) {
    $SESSIONS{$username} = $id if $check;
  }
}

BAIL_OUT('No sessions in DB') unless scalar keys %SESSIONS;

##

{
  my @CANONICALIZE_TESTS =
    ( # input, zone, result
     ['tEsT.TeSt.', 'test.test.', '@'],
     ['foo.test.test.', 'test.test.', 'foo'],
     ['Foo.tEst.teSt.', 'test.test.', 'Foo'],
     ['Foo.example.test.', 'test.test.', 'Foo.example.test.'],
     ['bar.foo', 'test.test.', 'bar.foo'],
     ['bar.foo.test.test', 'test.test.', 'bar.foo.test.test'],
     ['_bar._foo.test.test.', 'test.test.', '_bar._foo'],
     ['bAr.Foo.TesT.TesT.', 'test.test.', 'bAr.Foo'],
    );
  my $canonicalize_record_name_st = $dbh->prepare
    (q{SELECT regano.canonicalize_record_name(?,?)});

  foreach my $test (@CANONICALIZE_TESTS) {
    my ($result) = $dbh->selectrow_array
      ($canonicalize_record_name_st, {}, $test->[0], $test->[1]);
    is($result, $test->[2],
       qq{Canonicalize '$test->[0]' in zone '$test->[1]' as '$test->[2]'});
  }
}

sub update_zone ($$@) {
  my $zone_clear_st = $dbh->prepare
    (q{SELECT regano_api.zone_clear(?,?)});
  my %zone_add_st;
  $zone_add_st{SOA} = $dbh->prepare
    (q{SELECT regano_api.zone_add_SOA(?,?,?,?,?,?,?,?)});
  $zone_add_st{name} = $dbh->prepare
    (q{SELECT regano_api.zone_add_name(?,?,?,?,?,?)});
  $zone_add_st{text} = $dbh->prepare
    (q{SELECT regano_api.zone_add_text(?,?,?,?,?,?)});
  $zone_add_st{A} = $dbh->prepare
    (q{SELECT regano_api.zone_add_A(?,?,?,?,?)});
  $zone_add_st{AAAA} = $dbh->prepare
    (q{SELECT regano_api.zone_add_AAAA(?,?,?,?,?)});
  $zone_add_st{DS} = $dbh->prepare
    (q{SELECT regano_api.zone_add_DS(?,?,?,?,?,?,?,?)});
  $zone_add_st{MX} = $dbh->prepare
    (q{SELECT regano_api.zone_add_MX(?,?,?,?,?,?)});
  $zone_add_st{SRV} = $dbh->prepare
    (q{SELECT regano_api.zone_add_SRV(?,?,?,?,?,?,?,?)});

  my $session = shift;
  my $zone_name = shift;
  my @records = @_;

  $dbh->begin_work;
  $zone_clear_st->execute($session, $zone_name);
  $zone_clear_st->finish;
  foreach my $rec (@records) {
    my ($type, @args) = @$rec;

    $dbh->selectrow_array($zone_add_st{$type}, {}, $session, $zone_name, @args);
  }
  $dbh->commit;
}

sub convert_interval ($) {
  return $dbh->selectrow_array(qq{SELECT interval '$_[0]'}) if $_[0];
  return undef;
}

sub translate_zone ($@) {
  my $zone_name = shift;
  my @records_in = @_;
  my @records_out = ();
  my $canonicalize_record_name_st = $dbh->prepare
    (q{SELECT regano.canonicalize_record_name(?,?)});
  my $seq_no = 1;
  my %data_map = (name => 5, text => 6,
		  SOA => 7, A => 8, AAAA => 9,
		  DS => 10, MX => 11, SRV => 12);

  foreach my $rec (@records_in) {
    my ($type, $ttl, @args) = @$rec;
    my $rec_type;
    my @rec = (undef) x 13;

    if ($type eq 'name' || $type eq 'text') {
      $rec_type = splice @args, 1, 1;
    } else {
      $rec_type = $type;
    }

    $rec[0] = $type eq 'SOA' ? 0 : $seq_no++;
    $rec[1] = 'IN';
    $rec[2] = $rec_type;
    $rec[3] = convert_interval $ttl;

    unless ($type eq 'SOA') {
      $rec[4] = $dbh->selectrow_array($canonicalize_record_name_st, {},
				      shift @args, $zone_name);
      if (scalar @args > 1) {
	$rec[$data_map{$type}] = '('.join(',', @args).')';
      } else {
	$rec[$data_map{$type}] = $args[0];
      }
    }

    if ($type eq 'SOA') {
      my $hostmaster = shift @args;
      $rec[4] = '@';
      $rec[$data_map{$type}] = '('.join(',',$zone_name, $hostmaster,
					map {convert_interval $_} @args).')';
      unshift @records_out, \@rec;
    } else {
      push @records_out, \@rec;
    }
  }

  return @records_out;
}

{
  my $get_domain_records_st = $dbh->prepare
    (q{SELECT seq_no, class, type, ttl, name, data_name, data_text, }.
     join(', ', map {"data_RR_$_"} qw/SOA A AAAA DS MX SRV/).
     q{ FROM regano.domain_records WHERE domain_id = ?});
  my ($domain_id) = $dbh->selectrow_array
    (q{SELECT id FROM regano.domains
	 WHERE domain_name = 'test' AND domain_tail = '.test.'});

  $dbh->selectrow_array(q{SELECT regano_api.zone_clear(?,?)}, {},
			$SESSIONS{test1}, 'test.test.');
  update_zone $SESSIONS{test1}, 'test.test.';
  is_deeply($dbh->selectall_arrayref($get_domain_records_st, {}, $domain_id),
	    [],
	    q{Clear records for 'test.test.'});

  my (@ZONE_IN, @ZONE_OUT);
  @ZONE_IN =
    ([SOA => undef, 'hostmaster.test.test.',
      '12 hours', '5 min', '24 hours', '1 min'],
     [name => undef, 'zone', 'CNAME', 'ns'],
     [text => undef, 'test.test.', 'TXT', 'Sample text'],
     [A => '10 min', 'ns', '1.2.3.4'],
     [A => undef, 'mx', '1.2.3.5'],
     [AAAA => '11 min', 'ns', '::6'],
     [name => undef, 'sub', 'NS', 'ns'],
     # test data adapted from example in RFC 4034
     [DS => '12 min', 'sub',
      '60485', '5', '1', '2BB183AF5F22588179A53B0A98631FAD1A292118'],
     [MX => undef, '@', '10', 'mx.test.test.'],
     # test data adapted from example in RFC 2782
     [SRV => undef, '*._tcp', '0', '0', '0', '.'],
     [SRV => undef, '*._udp', '0', '0', '0', '.'],
    );
  @ZONE_OUT = translate_zone 'test.test.', @ZONE_IN;

  update_zone $SESSIONS{test1}, 'test.test.', @ZONE_IN;
  is_deeply($dbh->selectall_arrayref($get_domain_records_st, {}, $domain_id),
	    [@ZONE_OUT],
	    q{Set records for 'test.test.'});
}

##

$dbh->disconnect;

__END__
