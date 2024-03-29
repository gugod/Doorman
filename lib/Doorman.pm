package Doorman;
use 5.010;
our $VERSION = "0.10";
our $AUTHORITY = 'https://gugod.org';

1;

__END__

=head1 NAME

Doorman - The authentication middeleware collection for Plack.

=head1 DESCRIPTION

Doorman is a collection of psgi-based authentication middlewares for
web programmers. Your app can easily require an authenticated session.
The following middlewares are provided. Please consult their documentation
for further information.

=over 4

=item *

L<Plack::Middleware::DoormanAuthentication>

=item *

L<Plack::Middleware::DoormanOpenID>

=item *

L<Plack::Middleware::DoormanTwitter>

=item *

L<Plack::Middleware::DoormanAuth0>

=back

=head1 EXAMPLES

This distribution comes with several example plack apps under its
C<examples> directory for your references. You may also browse them
online: L<https://github.com/gugod/Doorman/tree/master/examples>

=head1 AUTHORS

    Kang-min Liu <gugod@gugod.org>
    Luke Closs   <me@luk.ec>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2011..* Kang-min Liu C<< <gugod@gugod.org> >>.

This is free software, licensed under:

    The MIT (X11) License

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
