use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Registrar;

ok( request('/registrar')->is_success, 'Request should succeed' );
done_testing();
