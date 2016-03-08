use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Verify;

ok( request('/verify')->is_success, 'Request should succeed' );
done_testing();
