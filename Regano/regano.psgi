use strict;
use warnings;

use Regano;

my $app = Regano->apply_default_middlewares(Regano->psgi_app);
$app;

