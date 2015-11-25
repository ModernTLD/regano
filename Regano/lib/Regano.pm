package Regano;
use Moose;
use namespace::autoclean;

use Catalyst::Runtime 5.80;

# Set flags and add plugins for the application.
#
# Note that ORDERING IS IMPORTANT here as plugins are initialized in order,
# therefore you almost certainly want to keep ConfigLoader at the head of the
# list if you're using it.
#
#         -Debug: activates the debug mode for very useful log messages
#   ConfigLoader: will load the configuration from a Config::General file in the
#                 application's home directory
# Static::Simple: will serve static files from the application's root
#                 directory

use Catalyst qw/
    -Debug
    ConfigLoader
    Static::Simple
/;

extends 'Catalyst';

our $VERSION = '0.01';

has 'InstanceName' => ( is => 'rw', isa => 'Str' );
has 'InstanceDescription' => ( is => 'rw', isa => 'Str' );

# Configure the application.
#
# Note that settings in regano.conf (or other external
# configuration file that you set up manually) take precedence
# over this when using ConfigLoader. Thus configuration
# details given here can function as a default configuration,
# with an external configuration file acting as an override for
# local deployment.

__PACKAGE__->config(
    name => 'Regano',
    # Disable deprecated behavior needed by old applications
    disable_component_resolution_regex_fallback => 1,
    enable_catalyst_header => 1, # Send X-Catalyst header
    InstanceName => 'Regano',
    InstanceDescription => 'unconfigured',
);
__PACKAGE__->config(
    # Configure the view
    'View::HTML' => {
	# Set the location for TT files
	INCLUDE_PATH => [
	    __PACKAGE__->path_to('root', 'src'),
	],
	# Use a standard wrapper
	WRAPPER => [ 'wrapper.tt' ],
    },
);

# Start the application
__PACKAGE__->setup();

=encoding utf8

=head1 NAME

Regano - A TLD management system for OpenNIC TLDs

=head1 SYNOPSIS

    script/regano_server.pl

=head1 DESCRIPTION

Regano is a domain registration and general TLD management system for
OpenNIC TLDs.  While it was initially developed for the .chan TLD, the
project aims for general applicability.

=head1 SEE ALSO

L<Regano::Controller::Root>, L<Catalyst>

=head1 AUTHOR

Pathore

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
