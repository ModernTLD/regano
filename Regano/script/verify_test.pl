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

our %config = (
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
    $config{$_} = $dbconf->{$_} for keys %$dbconf;
}

sub send_verify ($$$$) {
    my ($email, $name, $vid, $vkey) = @_;

    print "verify/$vid/$vkey for $email\n";

    return 1;
}

# adapted from DBD::Pg manual
 DBHLOOP: {
     my $dbh = DBI->connect($config{dsn},
			    $config{user},
			    $config{password},
			    $config{options});
     $dbh->ping() or die "bad DB handle";

     $dbh->do('LISTEN regano__contact_verifications');

   NOTIFYLOOP: {
       while (my $notify = $dbh->pg_notifies) {
	   my ($eventname, $pid, $payload) = @$notify;
	   if ($eventname eq 'regano__contact_verifications') {
	       $dbh->begin_work;
	       my $list_st = $dbh->prepare_cached
		   (q{SELECT v.id, v.key, c.email, c.name
			  FROM regano.contact_verifications v
			      JOIN regano.contacts c
				  ON v.user_id = c.owner_id
				    AND v.contact_id = c.id
			  WHERE NOT v.email_sent});
	       my $update_st = $dbh->prepare_cached
		   (q{UPDATE regano.contact_verifications
			  SET email_sent = TRUE
			  WHERE id = ? AND key = ?});
	       $list_st->execute;
	       my ($vid, $vkey, $email, $name);
	       $list_st->bind_columns(\ ($vid, $vkey, $email, $name));
	       while ($list_st->fetch) {
		   $update_st->execute($vid, $vkey)
		       if send_verify($email, $name, $vid, $vkey);
	       }
	       $dbh->commit;
	   }
       }
       $dbh->ping or redo DBHLOOP;
       { # adapted from example in perlfunc
	   my ($rin, $win, $ein, $rout, $wout, $eout, $bits);
	   $bits = ''; vec($bits, $dbh->{pg_socket},1) = 1;
	   $rin = $ein = $bits; $win = '';
	   select($rout=$rin, $wout=$win, $eout=$ein, undef);
       }
       redo NOTIFYLOOP;
     }
}

1;
