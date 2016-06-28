use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Registrar::Domain;

ok( request('/registrar/domain')->is_success, 'Request should succeed' );
done_testing();
