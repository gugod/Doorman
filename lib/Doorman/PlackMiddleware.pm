package Doorman::PlackMiddleware;
use strict;
use 5.010;
use feature qw(say switch);
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util::Accessor qw(root_url);

use Net::OpenID::Consumer;
use LWP::UserAgent;
use Data::Dumper qw(Dumper);
use Data::Thunk qw(lazy);

sub session_path { '/session' }
sub session_url  {
    my ($self) = @_;
    $self->root_url . session_path()
}

sub csr {
    my ($self, $request) = @_;
    $self->{csr} ||= Net::OpenID::Consumer->new(
        ua => LWP::UserAgent->new,
        args => sub { $request->param($_[0]) },
        consumer_secret => "lipsum",
        required_root   => $self->root_url
    );
}

sub call {
    my ($self, $env) = @_;

    $env->{'doorman.is_here'} = 1;

    my $request = Plack::Request->new($env);

    given([$request->method, $request->path]) {
        when(['POST', session_path]) {
            my $csr = $self->csr($request);
            my $claimed_identity = $csr->claimed_identity( $request->param("openid") );

            unless ($claimed_identity) {
                return [200, ["Content-Type" => 'text/html'], ["Error: " . $csr->errcode]];
            }

            my $check_url = $claimed_identity->check_url(
                delayed_return => 1,
                return_to      => $self->session_url,
                trust_root     => $self->root_url
            );

            return [302, ["Location" => $check_url], [""]];
        }

        when(['GET', session_path]) {
            $env->{'doorman.is_here_2'} = 1;

            my $csr = $self->csr($request);
            $csr->handle_server_response(
                verified => sub {
                    my $vident = shift;
                    $env->{'doorman.openid.verified_identity'} = $vident;
                    $env->{'doorman.openid.status'} = 'verified';
                },
                setup_required => sub {
                    $env->{'doorman.openid.status'} = 'setup_required';
                },
                cancelled      => sub {
                    $env->{'doorman.openid.status'} = 'cancelled';
                },
                not_openid     => sub {
                    $env->{'doorman.openid.status'} = 'not_openid';
                },
                error          => sub {
                    my $err = shift;
                    $env->{'doorman.openid.status'} = 'error';
                    $env->{'doorman.openid.error'} = $err;
                }
            );
        }
    }

    return $self->app->($env);
}

1;
