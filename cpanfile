requires 'Plack'                      => '1.0018';
requires 'Plack::Middleware::Session' => '0.18';
recommends "IO::Socket::SSL"          => "1.84";
recommends "Net::OpenID::Consumer"    => "1.13";
recommends "LWP::UserAgent"           => "6.04";
recommends "Net::Twitter::Lite"       => "0.12002";

on "test" => sub {
    requires "Test::More" => "0.98";
};
