#!/usr/bin/env perl

# plackup openid-auth.pl &; open http://localhost:5000

use strict;
use lib qw(lib ../lib);

use Data::Dumper;

my $app = sub {
    my $env = shift;

    # Retrive the Plack::Middleware::DoormanTwitter object
    my $doorman = $env->{'doorman.users.twitter'};

    my $status = $doorman->is_sign_in ? "Logged In As @{[ $doorman->twitter_screen_name ]}" : "Not Logged In";

    return [200, ['Content-Type' => 'text/html'], [
        qq{<html><body><nav>},
        qq{<a href="/">Home</a> },
        qq{<a href="/page1">Page 1</a> },
        qq{<a href="/page2">Page 2</a> },
        qq{<a href="/page3">Page 3</a> },
        $doorman->is_sign_in ? qq{ <a href="@{[ $doorman->sign_out_path ]}">Logout</a>} : qq{ <a href="@{[ $doorman->sign_in_path ]}">Login</a>},
        qq{</nav>},
        qq{<p>$status</p>},
        '<hr><pre>' . Data::Dumper->Dump([$env->{'psgix.session'}], ['session']) . "</pre>",
        '<hr><pre>' . Data::Dumper->Dump([$env], ['env']) . "</pre>",
        "</body></html>"
    ]];
};

use Plack::Builder;
builder {
    enable "Session::Cookie";
    enable "DoormanTwitter", root_url => 'http://localhost:5000', scope => 'users',
        consumer_key    => "XXX",
        consumer_secret => "XXX";
    $app;
};
