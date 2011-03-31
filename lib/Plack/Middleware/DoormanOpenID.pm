package Plack::Middleware::DoormanOpenID;
use 5.010;
use strict;
use feature qw(switch);
use parent 'Doorman::PlackMiddleware';

use Plack::Request;
use Plack::Util::Accessor qw(root_url scope);

use Net::OpenID::Consumer;
use LWPx::ParanoidAgent;
use URI;
use Scalar::Util qw(weaken);
use Plack::Session;

sub openid_verified_uri {
    my ($self) = @_;
    return $self->scope_uri . "/openid_verified";
}

sub openid_verified_path {
    my ($self) = @_;
    return URI->new($self->openid_verified_uri)->path;
}

sub verified_identity_url {
    my ($self) = @_;
    my $env = $self->{env};
    my $scope = $self->scope;
    my $session = Plack::Session->new($env);

    return $session->get("doorman.${scope}.openid.verified_identity_url");
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
    my $session = Plack::Session->new($env);
    die "Session is required for Doorman.\n" unless $session;

    $env->{"doorman.@{[ $self->scope ]}.openid"} = $self;

    $self->{env} = $env;
    weaken($self->{env});

    my $request = Plack::Request->new($env);

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

                    $session->set('doorman.'. $self->scope .'.openid.verified_identity_url', $id->url);
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
            $session->remove('doorman.'. $self->scope .'.openid.verified_identity_url');
        }
    }

    return $self->app->($env);
}

1;

__END__

=head1 NAME

Plack::Middleware::DoormanOpenID - The OpenID sign-in middleware.

=head1 SYNOPSIS

    use Plack::Builder;
    builder {
        enable "Session::Cookie";
        enable "DoormanOpenID", root_url => 'http://localhost:5000', scope => 'users';

        sub {
            my $env = shift;
            my $doorman = $env->{'doorman.users.openid'};

        }
    };

=head1 DESCRIPTION

=he1d METHODS

=over 4

=item * is_sign_in

Returns true if the current session is considered signed in.

=item * verified_identity_url

Returns the verified OpenID URL if current session is sign in. Returns undef otherwise.

=item * sign_in_path, sign_in_url

Returns a path, or full url, that is used to let user POST an openid
url to sign in. It should be used as the value of "action" attribute
of a form. For example:

    my $doorman = $env->{'doorman.users.openid'};

    my $sign_in_form = <<HTML;
    <form method="POST" action="@{[ $doorman->sign_in_path ]}">
        <label for="openid">OpenID</label>
        <input type="text" id="openid" name="openid" autofocus>
        <input type="submit" value="Sign In">
    </form>
    HTML

At this point you need to name the parameter C<openid>.

=item * sign_out_path, sign_out_url

Returns a path that, when visited, wipes out the signed in information in the session.

=back
