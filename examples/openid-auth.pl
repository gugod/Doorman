#!/usr/bin/env perl

# plackup openid-auth.pl &; open http://localhost:5000

use strict;
use feature qw(switch say);

use Plack;
use Plack::Request;
use Net::OpenID::Consumer;
use LWP::UserAgent;
use Data::Dumper qw(Dumper);

sub root_url()     { 'http://localhost:5000' }
sub root_path()    { '/' }
sub session_path() { '/session' }
sub session_url()  { root_url . '/session' }

my $app = sub {
    my $env = shift;
    my $request = Plack::Request->new($env);
    my $csr = Net::OpenID::Consumer->new(
        ua => LWP::UserAgent->new,
        args => sub { $request->param($_[0]) },
        consumer_secret => "?",
        required_root   => root_url
    );

    given([$request->method, $request->path]) {
        when(['GET', '/']) {
            return [
                200,
                ['Content-Type' => 'text/html'],
                [qq{<html><form method="post" action="@{[ session_path ]}">OpenID:<input type="text" name="openid"><input type="submit"></form></html>}]
            ];
        }

        when(['POST', session_path]) {
            my $claimed_identity = $csr->claimed_identity( $request->param("openid") );

            unless ($claimed_identity) {
                return [200, ["Content-Type" => 'text/html'], ["Error: " . $csr->errcode]];
            }

            my $check_url = $claimed_identity->check_url(
                delayed_return => 1,
                return_to => session_url,
                trust_root => root_url
            );

            return [302, ["Location" => $check_url], [""]];
        }

        when(['GET', session_path]) {
            my $status = "UNKNOWN";

            $csr->handle_server_response(
                verified => sub {
                    my $vident = shift;
                    $status = "Verified as @{[ $vident->display ]}";
                },
                setup_required => sub {
                    $status = "setup_required"
                },
                cancelled => sub {
                    $status = 'cancelled'
                },
                error => sub {
                    my $err = shift;
                    $status = "Error: $err";
                }
            );

            return [
                200,
                ['Content-Type' => 'text/html'],
                [qq{<h1>${status}</h1><a href="/">Home</a><pre>} . Dumper($request->query_parameters) . "</pre><hr><pre>" . Dumper($env) . "</pre>"]
            ];
        }
    }

    return [200, [], ['<pre>' . Dumper($env) . "</pre>"]];
};

$app;
