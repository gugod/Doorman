package Doorman::PlackMiddleware;
use 5.010;
use parent 'Plack::Middleware';
use Plack::Util::Accessor qw(root_url scope scope_object);

use Doorman;
our $VERSION   = $Doorman::VERSION;
our $AUTHORITY = $Doorman::AUTHORITY;

use Doorman::Scope;

sub prepare_app {
    my $self = shift;
    $self->scope('users') unless $self->scope;

    unless ($self->scope_object) {
        my $scope_object = Doorman::Scope->new(name => $self->scope);
        $scope_object->root_url($self->root_url) if $self->root_url;
        $self->scope_object( $scope_object );
    }

    return $self;
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

1;
