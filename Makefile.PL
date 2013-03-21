use strict;
use warnings;
use inc::Module::Install;

all_from 'lib/Doorman.pm';

requires
    'Plack' => '1.0018',
    'Plack::Middleware::Session' => '0.18';

feature "OpenID Middleware" =>
    -default => 0,
    recommends('IO::Socket::SSL' => '1.84',
               'Net::OpenID::Consumer' => '1.13',
               'LWP::UserAgent' => '6.04');

feature "Twitter Middleware" =>
    -default => 0,
    recommends('Net::Twitter::Lite' => '0.12002');

build_requires  'Test::More'        => '0.98';

tests 't/*.t';
author_tests 'xt';

WriteAll;
