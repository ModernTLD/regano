use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Zone;

ok( request('/zone')->is_success, 'Request should succeed' );
done_testing();
