use strict;
use warnings;
use inc::Module::Install;

all_from 'lib/Doorman.pm';

requires
    'Plack' => '1.0018',
    'Plack::Middleware::Session' => '0.18';

feature "OpenID Middleware" =>
    -default => 0,
    recommends('IO::Socket::SSL' => '1.39',
               'Net::OpenID::Consumer' => '1.03',
               'LWP::UserAgent' => '6.04');

feature "Twitter Middleware" =>
    -default => 0,
    recommends('Net::Twitter::Lite' => '1.03');

build_requires  'Test::More'        => '0.98';

tests 't/*.t';
author_tests 'xt';

WriteAll;
