use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Domain;

ok( request('/domain')->is_success, 'Request should succeed' );
done_testing();
