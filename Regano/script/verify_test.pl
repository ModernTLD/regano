#!/usr/bin/env perl

=head1 NAME

verify_test.pl - Regano contact verification testing tool

=head1 SYNOPSIS

verify_test.pl

=head1 DESCRIPTION

Monitor for new contact verification requests and print information.

=head1 AUTHOR

Pathore

=head1 LICENSE

This program is free software. You can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

use strict;
use warnings;

use Config::General;
use DBI;

use WWW::Mechanize;

our %config = (
  InstanceBase  => 'http://localhost:3000',
  dsn           => 'dbi:Pg:db=regano',
  user          => '',
  password      => '',
  options       => { AutoCommit => 1, RaiseError => 1 },
);
{
    my $configfile;
    ($configfile = $0) =~ s~script/[^/]*$~regano.conf~;
    $configfile = $ENV{REGANO_CONFIG} if $ENV{REGANO_CONFIG};
    my $reader = Config::General->new($configfile);
    my %contents = $reader->getall();
    my $confkey = (grep {m/^DB,/} keys %{$contents{Model}})[0];
    my $dbconf = $contents{Model}{$confkey};
    $config{InstanceBase} = $contents{InstanceBase} if $contents{InstanceBase};
    $config{$_} = $dbconf->{$_} for keys %$dbconf;
}

our @URLS = ();

sub send_verify ($$$$) {
    my ($email, $name, $vid, $vkey) = @_;

    print "$email:\n  $config{InstanceBase}/verify/$vid/$vkey\n";
    push @URLS, join('/', $config{InstanceBase}, 'verify', $vid, $vkey);

    return 1;
}

sub process_verifications ($) {
    my $dbh = shift;
    my $count = 0;
    my $list_st = $dbh->prepare_cached
	(q{SELECT v.id, v.key, c.email, c.name
	       FROM regano.contact_verifications v
		   JOIN regano.contacts c
		       ON v.user_id = c.owner_id AND v.contact_id = c.id
	       WHERE NOT v.email_sent});
    my $update_st = $dbh->prepare_cached
	(q{UPDATE regano.contact_verifications
	       SET email_sent = TRUE
	       WHERE id = ? AND key = ?});
    my ($vid, $vkey, $email, $name);

    $dbh->begin_work;

    $list_st->execute;
    $list_st->bind_columns(\ ($vid, $vkey, $email, $name));

    while ($list_st->fetch) {
	$update_st->execute($vid, $vkey)
	    if send_verify($email, $name, $vid, $vkey);
	$count++;
    }

    $dbh->commit;

    return $count;
}

sub verify_emails () {
    my $mech = WWW::Mechanize->new();

    while (@URLS) {
	$mech->get($URLS[-1]);
	print "$URLS[-1]: ";
	if ($mech->text() =~ m/Contact verified successfully\./) {
	    print "success\n";
	} elsif ($mech->text() =~ m/Contact verification failed\./) {
	    print "failure\n";
	} else {
	    print "???\n";
	}
	pop @URLS;
    }
}

# adapted from DBD::Pg manual
 DBHLOOP: {
     my $dbh = DBI->connect($config{dsn},
			    $config{user},
			    $config{password},
			    $config{options});
     $dbh->ping() or die "bad DB handle";

     $dbh->do('LISTEN regano__contact_verifications');
     process_verifications($dbh);

   NOTIFYLOOP: {
       while (my $notify = $dbh->pg_notifies) {
	   my ($eventname, $pid, $payload) = @$notify;
	   if ($eventname eq 'regano__contact_verifications') {
	       process_verifications($dbh);
	   }
       }
       verify_emails();
       { # adapted from example in perlfunc
	   my ($rin, $win, $ein, $rout, $wout, $eout, $bits);
	   $bits = ''; vec($bits, $dbh->{pg_socket},1) = 1;
	   $rin = $ein = $bits; $win = '';
	   select($rout=$rin, $wout=$win, $eout=$ein, undef);
       }
       $dbh->ping or redo DBHLOOP;
       redo NOTIFYLOOP;
     }
}

1;
