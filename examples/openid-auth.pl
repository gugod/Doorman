#!/usr/bin/env perl

# plackup openid-auth.pl &; open http://localhost:5000

use strict;
use lib qw(lib ../lib);

use Data::Dumper;

my $app = sub {
    my $env = shift;
    my $doorman = $env->{'doorman.openid'};

    my $status = $doorman->is_sign_in ? "Logged In As @{[ $doorman->verified_identity->display ]}" : "Not Logged In";


    return [200, ['Content-Type' => 'text/html'], [
        qq{<html><body><nav>},
        qq{<a href="/">Home</a> },
        $doorman->is_sign_in ? qq{ <a href="@{[ $doorman->sign_out_path ]}">Logout</a>} : qq{},
        qq{</nav>},
        qq{<p>$status</p>},
        qq{<form method="post" action="@{[ $doorman->sign_in_path ]}">OpenID:<input type="text" name="openid" autofocus><input type="submit" value="Sign In"></form></html>},
        '<hr><pre>' . Data::Dumper->Dump([$env], ['env']) . "</pre>",
        "</body></html>"
    ]];
};

use Plack::Builder;
builder {
    enable "Session::Cookie";
    enable "DoormanOpenID", root_url => 'http://localhost:5000', scope => 'users';
    $app;
};
