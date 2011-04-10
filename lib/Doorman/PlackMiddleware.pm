package Doorman::PlackMiddleware;
use 5.010;
use parent 'Plack::Middleware';
use Plack::Util::Accessor qw(root_url scope);

use Doorman;
our $VERSION   = $Doorman::VERSION;
our $AUTHORITY = $Doorman::AUTHORITY;

use Doorman::Scope;
use Scalar::Util qw(weaken);

sub prepare_app {
    my $self = shift;
    $self->scope('users') unless $self->scope;
    return $self;
}

sub scope_object {
    my ($self, $obj) = @_;

    if ($obj) {
        $self->{scope_object} = $obj;
        return $obj;
    }

    unless ($self->{scope_object}) {
        my $obj = Doorman::Scope->new( name => $self->scope, root_url => $self->root_url );
        $self->{scope_object} = $obj;
    }

    return $self->{scope_object};
}

# STUB
sub is_sign_in {
    my ($self) = @_;
    die "Unimplemented: @{[ ref($self )]}->is_sign_in must be implemented.";
}

# DELEGATE
{
    no strict 'refs';
    for my $method (qw(scope_url sign_in_url sign_out_url scope_path sign_in_path sign_out_path)) {
        *{ __PACKAGE__ . "::$method" } = sub {
            $_[0]->scope_object->$method;
        };
    }
}

sub prepare_call {
    my ($self, $env) = @_;
    my $request = Plack::Request->new($env);

    $self->{env} = $env;
    weaken($self->{env});

    if (!$self->root_url) {
        my $root_uri = $request->uri;
        $root_uri->path("");
        $self->root_url($root_uri->as_string);
    }

    if ($env->{"doorman." . $self->scope}) {
        $self->scope_object($env->{"doorman." . $self->scope});
    }
    else {
        $env->{"doorman." . $self->scope} = $self->scope_object;
    }

    return $self;
}

1;
