package Plack::Middleware::DoormanOpenID;

use strict;
use parent qw(Plack::Middleware);

use 5.010;
use feature qw(say switch);

use Plack::Request;
use Plack::Util::Accessor qw(root_url scope);

use Net::OpenID::Consumer;
use LWPx::ParanoidAgent;
use URI;
use Scalar::Util qw(weaken);

sub scope_uri  {
    my ($self) = @_;
    $self->root_url . '/' . $self->scope()
}

sub sign_in_uri {
    my ($self) = @_;
    return $self->scope_uri . "/sign_in";
}

sub sign_out_uri {
    my ($self) = @_;
    return $self->scope_uri . "/sign_out";
}

sub openid_verified_uri {
    my ($self) = @_;
    return $self->scope_uri . "/openid_verified";
}

sub sign_in_path {
    my ($self) = @_;
    return URI->new($self->sign_in_uri)->path;
}

sub sign_out_path {
    my ($self) = @_;
    return URI->new($self->sign_out_uri)->path;
}

sub openid_verified_path {
    my ($self) = @_;
    return URI->new($self->openid_verified_uri)->path;
}

sub verified_identity_url {
    my ($self) = @_;
    my $env = $self->{env};
    my $scope = $self->scope;
    my $session = $env->{'psgix.session'};

    if ($session && $session->{"doorman.${scope}.openid.verified_identity_url"}) {
        return $session->{"doorman.${scope}.openid.verified_identity_url"};
    }

    if ($env->{"doorman.${scope}.openid.verified_identity"}) {
        return $env->{"doorman.${scope}.openid.verified_identity"}->url;
    }

    return;
}

sub is_sign_in {
    my ($self) = @_;
    return defined $self->verified_identity_url;
}

sub csr {
    my ($self, $request) = @_;
    return Net::OpenID::Consumer->new(
        ua => LWPx::ParanoidAgent->new,
        args => sub { $request->param($_[0]) },
        consumer_secret => "lipsum",
        required_root   => $self->root_url
    );
}

sub call {
    my ($self, $env) = @_;

    $env->{'doorman.openid'} = $self;

    $self->{env} = $env;
    weaken($self->{env});

    my $request = Plack::Request->new($env);
    my $session = $env->{'psgix.session'};

    given([$request->method, $request->path]) {
        when(['POST', $self->sign_in_path]) {
            my $csr = $self->csr($request);
            my $claimed_identity = $csr->claimed_identity( $request->param("openid") );

            unless ($claimed_identity) {
                return [200, ["Content-Type" => 'text/html'], ["Error: " . $csr->errcode]];
            }

            my $check_url = $claimed_identity->check_url(
                delayed_return => 1,
                return_to      => $self->openid_verified_uri,
                trust_root     => $self->root_url
            );

            return [302, ["Location" => $check_url], [""]];
        }

        when(['GET', $self->openid_verified_path]) {
            my $csr = $self->csr($request);
            $csr->handle_server_response(
                verified => sub {
                    my $id = shift;

                    $env->{'doorman.'. $self->scope .'.openid.verified_identity'} = $id;
                    $env->{'doorman.'. $self->scope .'.openid.status'} = 'verified';

                    if ($session) {
                        $session->{'doorman.'. $self->scope .'.openid.verified_identity_url'} = $id->url;
                    }
                },
                setup_required => sub {
                    $env->{'doorman.'. $self->scope .'.openid.status'} = 'setup_required';
                },
                cancelled      => sub {
                    $env->{'doorman.'. $self->scope .'.openid.status'} = 'cancelled';
                },
                not_openid     => sub {
                    $env->{'doorman.'. $self->scope .'.openid.status'} = 'not_openid';
                },
                error          => sub {
                    my $err = shift;
                    $env->{'doorman.'. $self->scope .'.openid.status'} = 'error';
                    $env->{'doorman.'. $self->scope .'.openid.error'} = $err;
                }
            );
        }

        when(['GET', $self->sign_out_path]) {
            if ($session) {
                delete $session->{'doorman.'. $self->scope .'.openid.verified_identity_url'};
            }
        }
    }

    return $self->app->($env);
}

1;
