#!/usr/bin/env perl
use strict;
use warnings;
use 5.010;
use Test::More;

use Plack::Builder;
use Plack::Test;

test_psgi
    app => builder {
        enable "Session";
        enable "DoormanAuthentication", authenticator => sub {
            my ($login, $password) = @_;
            return $login;
        };

        sub {
            my ($env) = @_;
            my $body = "NOT SIGN IN";
            # require YAML;
            # print YAML::Dump($env);
            my $doorman = $env->{"doorman.users.authentication"};
            if ($doorman && $doorman->is_sign_in) {
                $body = "SIGN IN";
            }

            return [200, ["Content-Type" => "text/plain"],  [$body]];
        };
    },
    client => sub {
        my ($cb) = @_;

        {
            my $res = $cb->(HTTP::Request->new(GET => "http://localhost/xd"));
            is $res->content, 'NOT SIGN IN';
        }

        {
            my $res = $cb->(HTTP::Request->new(
                POST => "http://localhost/users/sign_in",
                undef,
                "username=ohai&password=some"
            ));

            ok $res->is_success;
            is $res->content, 'SIGN IN';
        }

        {
            $cb->(HTTP::Request->new(GET => "http://localhost/users/sign_out"));
            my $res = $cb->(HTTP::Request->new(GET => "http://localhost/foo"));

            ok $res->is_success;
            is $res->content, 'NOT SIGN IN';
        }
    };

done_testing;
