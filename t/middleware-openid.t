#!/usr/bin/env perl
use strict;
use warnings;
use 5.010;
use Test::More;

use Plack::Middleware::DoormanOpenID;

{
    my $mw = Plack::Middleware::DoormanOpenID->new;
    $mw->prepare_app;

    is $mw->scope_path, "/users";
    is $mw->sign_in_path, "/users/sign_in";
    is $mw->sign_out_path, "/users/sign_out";

    is $mw->openid_verified_path, "/users/openid_verified";
}

{
    my $mw = Plack::Middleware::DoormanOpenID->new( root_url => "http://example.com/app");
    $mw->prepare_app;

    is $mw->scope_url,    "http://example.com/app/users";
    is $mw->sign_in_url,  "http://example.com/app/users/sign_in";
    is $mw->sign_out_url, "http://example.com/app/users/sign_out";

    is $mw->openid_verified_url, "http://example.com/app/users/openid_verified";
}

done_testing;
