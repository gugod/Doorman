package Doorman::PlackMiddleware;
use 5.010;
use parent 'Plack::Middleware';

use Doorman;
our $VERSION   = $Doorman::VERSION;
our $AUTHORITY = $Doorman::AUTHORITY;

# STUB
sub is_sign_in {
    my ($self) = @_;
    die "Unimplemented: @{[ ref($self )]}->is_sign_in must be implemented.";
}

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

sub sign_in_path {
    my ($self) = @_;
    return URI->new($self->sign_in_uri)->path;
}

sub sign_out_path {
    my ($self) = @_;
    return URI->new($self->sign_out_uri)->path;
}

1;

