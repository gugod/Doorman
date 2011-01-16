use strict;
use warnings;
use inc::Module::Install;

all_from 'lib/Doorman.pm';

requires 'Plack' => '0.9963';

feature "OpenID Middleware" =>
    -default => 0,
    recommends('Net::OpenID::Consumer' => '1.03',
               'LWPx::ParanoidAgent' => '1.07');

feature "Twitter Middleware" =>
    -default => 0,
    recommends('Net::Twitter::Lite' => '1.03');

build_requires  'Test::More'        => '0.42';

tests 't/*.t';
author_tests 'xt';

WriteAll;
