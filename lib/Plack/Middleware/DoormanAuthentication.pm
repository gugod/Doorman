package Plack::Middleware::DoormanAuthentication;
use 5.010;
use strict;

use Doorman;
our $VERSION   = $Doorman::VERSION;
our $AUTHORITY = $Doorman::AUTHORITY;

use feature qw(switch);
use parent 'Doorman::PlackMiddleware';

use Plack::Util::Accessor qw(root_url scope authenticator);
use Plack::Session;

use Scalar::Util qw(weaken);

sub prepare_app {
    my $self = shift;
    $self->scope('users') unless $self->scope;
}

sub _session_key {
    my ($self, $key) = @_;
    return "doorman." . $self->scope . ".authentication" . ( $key ? ".$key" : "");
}

sub is_sign_in {
    my ($self) = @_;
    my $env = $self->{env};
    my $session = Plack::Session->new($env);
    return $session->get( $self->_session_key("authenticated") );
}

sub call {
    my ($self, $env) = @_;
    my $session = Plack::Session->new($env);
    die "Session is required for Doorman.\n" unless $session;

    my $request = Plack::Request->new($env);

    if (!$self->root_url) {
        my $root_uri = $request->uri;
        $root_uri->path("");
        $self->root_url($root_uri->as_string);
    }

    $env->{ $self->_session_key } = $self;
    $self->{env} = $env;
    weaken($self->{env});

    given([$request->method, $request->path]) {
        when(['POST', $self->sign_in_path]) {
            my $success = $self->authenticator->($self, $request->param("login"), $request->param("password"));
            if ($success) {
                $session->set($self->_session_key("authenticated"), $success);
            }
        }

        when(['GET', $self->sign_out_path]) {
            $session->remove( $self->_session_key );
        }
    }

    return $self->app->($env);
}

1;
