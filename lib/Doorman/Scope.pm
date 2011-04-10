package Doorman::Scope;
use strict;
use Plack::Util::Accessor qw(name root_url);
use URI;

sub new {
    my $class = shift;
    return bless { root_url => "http://localhost", name => "users", @_ }, $class;
}

sub scope_url  {
    $_[0]->root_url . '/' . $_[0]->name;
}

sub scope_path  {
    return URI->new($_[0]->scope_url)->path;
}

no strict 'refs';

for my $x (qw(in out up)) {
    *{ __PACKAGE__ . "::sign_${x}_url" } = sub {
        return $_[0]->scope_url . "/sign_${x}";
    };

    *{ __PACKAGE__ . "::sign_${x}_path" } = sub {
        my $method = "sign_${x}_url";
        return URI->new($_[0]->$method)->path;
    };
}

1;
