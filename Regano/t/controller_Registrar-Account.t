use strict;
use warnings;
use Test::More;


use Catalyst::Test 'Regano';
use Regano::Controller::Registrar::Account;

ok( request('/registrar/account')->is_success, 'Request should succeed' );
done_testing();
