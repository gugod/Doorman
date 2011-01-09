package Plack::Middleware::DoormanTwitter;
use 5.010;
use parent 'Doorman::PlackMiddleware';
use strict;
use feature qw(say switch);
use Plack::Request;
use Plack::Util::Accessor qw(root_url scope consumer_key consumer_secret);
use URI;
use Scalar::Util qw(weaken);
use Net::Twitter::Lite;

sub twitter {
    my ($self) = @_;

    my $nt = Net::Twitter::Lite->new(
        consumer_key    => $self->consumer_key,
        consumer_secret => $self->consumer_secret
    );

    my $access = $self->twitter_access;
    if ($access) {
        $nt->access_token($access->{access_token});
        $nt->access_token_secret($access->{access_token_secret});
    }

    return $nt;
}

sub twitter_access {
    my ($self) = @_;
    my $env = $self->{env};
    my $session = $env->{'psgix.session'};
    my $scope = $self->scope;

    my $t = $session->{"doorman.${scope}.twitter"};

    if ($t->{"access_token"} && $t->{"access_token_secret"}) {
        return {
            access_token        => $t->{"access_token"},
            access_token_secret => $t->{"access_token_secret"}
        }
    }

    return;
}

sub twitter_verified_uri {
    my ($self) = @_;
    return $self->scope_uri . "/twitter_verified";
}

sub twitter_verified_path {
    my ($self) = @_;
    return URI->new($self->twitter_verified_uri)->path;
}

sub twitter_screen_name {
    my ($self) = @_;
    my $session = $self->{env}->{'psgix.session'};
    my $k = "doorman.@{[ $self->scope ]}.twitter";

    return unless $session && $session->{$k};

    return $session->{$k}{"screen_name"};
}

sub is_sign_in {
    my ($self) = @_;
    return defined $self->twitter_screen_name;
}

sub call {
    my ($self, $env) = @_;

    $self->{env} = $env;
    weaken($self->{env});

    $env->{"doorman.@{[ $self->scope ]}.twitter"} = $self;

    my $request = Plack::Request->new($env);
    my $session = $env->{'psgix.session'} or die "Session is required for Twitter OAuth.";

    given([$request->method, $request->path]) {
        when(['GET', $self->sign_in_path]) {
            my $nt = $self->twitter;
            my $url = $nt->get_authentication_url(callback => $self->twitter_verified_uri);

            $session->{"doorman.@{[ $self->scope ]}.twitter.oauth"} = {
                token => $nt->request_token,
                token_secret => $nt->request_token_secret
            };

            return [302, [Location => $url->as_string], ['']];
        }

        when(['GET', $self->twitter_verified_path]) {
            my $verifier = $request->param('oauth_verifier');
            my $oauth = $session->{"doorman.@{[ $self->scope ]}.twitter.oauth"};
            my $nt = $self->twitter;
            $nt->request_token($oauth->{token});
            $nt->request_token_secret($oauth->{token_secret});

            my ($access_token, $access_token_secret, $user_id, $screen_name)
                = $nt->request_access_token(verifier => $verifier);

            $session->{"doorman.@{[ $self->scope ]}.twitter"} = {
                access_token        => $access_token,
                access_token_secret => $access_token_secret,
                user_id             => $user_id,
                screen_name         => $screen_name
            };

            delete $session->{"doorman.@{[ $self->scope ]}.twitter.oauth"};
        }

        when(['GET', $self->sign_out_path]) {
            if ($session) {
                delete $session->{"doorman.@{[$self->scope]}.twitter"};
            }
        }
    }

    return $self->app->($env);
}

1;
