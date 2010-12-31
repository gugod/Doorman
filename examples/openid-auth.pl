#!/usr/bin/env perl

# plackup openid-auth.pl &; open http://localhost:5000

use strict;
use feature qw(switch say);

use lib qw(lib ../lib);

use Plack;

use Data::Dumper;

sub session_path() { '/session' }

my $app = sub {
    my $env = shift;

    my $status = "Not Logged In";

    if ($_ = $env->{'doorman.openid.verified_identity'}) {
        $status = "Logged In As @{[ $_->display ]}";
    }

    return [200, ['Content-Type' => 'text/html'], [
        qq{<html><body>},
        qq{<nav><a href="/">Home</a></nav>},
        qq{<p>$status</p>},
        qq{<form method="post" action="@{[ session_path ]}">OpenID:<input type="text" name="openid" autofocus><input type="submit" value="Sign In"></form></html>},
        '<hr><pre>' . Data::Dumper->Dump([$env], ['env']) . "</pre>",
        "</body></html>"
    ]];
};

# use Doorman::PlackMiddleware;
# $app = Doorman::PlackMiddleware->wrap($app, root_url => 'http://localhost:5000');
# $app;

use Plack::Builder;
builder {
    enable "DoormanOpenID", root_url => 'http://localhost:5000';
    $app;
};
