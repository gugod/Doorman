#!/usr/bin/env perl

# plackup openid-auth.pl &; open http://localhost:5000

use strict;
use feature qw(switch say);

use Plack;
use Plack::Request;
use Net::OpenID::Consumer;
use LWP::UserAgent;
use Data::Dumper qw(Dumper);

my $app = sub {
    my $env = shift;
    my $request = Plack::Request->new($env);

    given($request->path) {
        when('/') {
            return [
                200,
                ['Content-Type' => 'text/html'],
                ['<html><form method="post" action="/doorman/openid/login">OpenID:<input type="text" name="openid"><input type="submit"></form></html>']
            ];
        }

        when('/doorman/openid/login') {
            my $csr = Net::OpenID::Consumer->new(
                ua => LWP::UserAgent->new,
                args => sub { $request->param($_[0]) },
                consumer_secret => "?",
                required_root   => "http://localhost:5000",
            );

            my $claimed_identity = $csr->claimed_identity( $request->param("openid") );

            unless ($claimed_identity) {
                return [200, ["Content-Type" => 'text/html'], ["Error: " . $csr->errcode]];
            }

            my $check_url = $claimed_identity->check_url(
                delayed_return => 1,
                return_to => "http://localhost:5000/doorman/openid/verified",
                trust_root => "http://localhost:5000/",
            );

            return [302, ["Location" => $check_url], [""]];
        }

        when('/doorman/openid/verified') {
            return [
                200,
                ['Content-Type' => 'text/html'],
                ['<h1>Verified</h1><a href="/">Home</a><pre>' . Dumper($request->query_parameters) . "</pre><hr><pre>" . Dumper($env) . "</pre>"]
            ];
        }
    }

    return [200, [], ['<pre>' . Dumper($env) . "</pre>"]];
};
