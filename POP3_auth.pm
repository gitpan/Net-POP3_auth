# Net::POP3_auth.pm
#
# alex pleiner 2003, zeitform Internet Dienste
# thanks to Graham Barr <gbarr@pobox.com> for Net::POP3
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# Net::POP3_auth is a small extension to G. Barr's Net::POP3
# to authenticate to an POP3 server using one of the AUTH methods
# APOP, CRAM-MD5 or PLAIN. This module can be expanded and is a
# very first implementation.

package Net::POP3_auth;

require 5.001;

use strict;
use vars qw($VERSION @ISA);
use Socket 1.3;
use Carp;
use IO::Socket;
use Net::Cmd;
use Net::Config;
use Net::POP3;
use MIME::Base64;
use Digest::HMAC_MD5 qw(hmac_md5_hex);

$VERSION = "0.02";

@ISA = qw(Net::POP3);

# all other method taken from Net::SMTP

sub auth_types {
  @_ == 1 or croak 'usage: $pop3->auth_types()';
  my $me = shift;

  return undef
     unless $me->_CAPA;

  my @auth;
  foreach (@{$me->read_until_dot}) { 
    push @auth, "APOP" if /^APOP/;
    push @auth, split(/\s+/, $1) if /^SASL (.+)$/;
  }
  return undef unless @auth;
  return wantarray ? @auth : join " ", @auth;
}

sub auth {
  @_ == 4 or croak 'usage: $pop3->auth( AUTH, USER, PASS )';
  my ($me, $auth_type, $user, $pass) = @_;

  ## go for auth cram-md5
  if (uc($auth_type) eq "CRAM-MD5") {

    $me->_AUTH("CRAM-MD5");
    (my $stamp) = ($me->message =~ /^\+\s+(.+)$/);
    return undef unless $stamp;

    my $hmac = hmac_md5_hex(decode_base64($stamp), $pass);
    my $answer = encode_base64($user . " " . $hmac); $answer =~ s/\n//g;
    return undef
      unless $me->command($answer)->response() == CMD_OK;
    return $me->_get_mailbox_count();

  ## go for auth plain
  } elsif (uc($auth_type) eq "PLAIN") {

    return $me->login($user, $pass);

  ## go for apop
  } elsif (uc($auth_type) eq "APOP") {

    return $me->apop($user, $pass);

  ## other auth methods not supported
  } else {
    carp "Net::POP3_auth: authentication type \"$auth_type\" not supported";
    return;
  }

}


sub _AUTH { shift->command("AUTH", @_)->response() } ## will not match CMD_OK
sub _CAPA { shift->command("CAPA")->response() == CMD_OK }

1;


__END__

=head1 NAME

Net::POP3_auth - Post Office Protocol 3 Client with AUTHentication

=head1 SYNOPSIS

    use Net::POP3_auth;

    # Constructors
    $pop = Net::POP3_auth->new('mailhost');
    $pop = Net::POP3_auth->new('mailhost', Timeout => 60);

=head1 DESCRIPTION

This module implements a client interface to the POP3 protocol AUTH 
service extension, enabling a perl5 application to talk to and 
authenticate against POP3 servers. This documentation assumes 
that you are familiar with the concepts of the POP3 protocol described 
in RFC1939 and with the AUTH service extension described in RFC1734.

A new Net::POP3_auth object must be created with the I<new> method. Once
this has been done, all POP3 commands are accessed through this object.

The Net::POP3_auth class is a subclass of Net::POP3, which itself is
a subclass of Net::Cmd and IO::Socket::INET.

=head1 EXAMPLES

This example authenticates via CRAM-MD5 and lists all available messages
for the user at the POP3 server known as mailhost:

    #!/usr/bin/perl -w

    use Net::POP3_auth;

    $pop = Net::POP3_auth->new('mailhost');
    $pop->auth('CRAM-MD5', 'user', 'password');

    print $pop->list;
    $pop->quit;

=head1 CONSTRUCTOR

=over 4

=item new Net::POP3_auth [ HOST, ] [ OPTIONS ]

This is the constructor for a new Net::POP3_auth object. It is
taken from Net::POP3 as all other methods (except I<auth> and 
I<auth_types>) are, too.

=head1 METHODS

Unless otherwise stated all methods return either a I<true> or I<false>
value, with I<true> meaning that the operation was a success. When a method
states that it returns a value, failure will be returned as I<undef> or an
empty list.

=over 4

=item auth_types ()

Returns the AUTH methods supported by the server as an array or in a space 
separated string. This list is exacly the line given by the POP3 server after
the C<CAPA> command containing the keyword C<AUTH> and the method APOP if 
the C<CAPA> command contains the keyword C<APOP>.

=item auth ( AUTH, USER, PASSWORD )

Authenticates the user C<USER> via the authentication method C<AUTH>
and the password C<PASSWORD>. Returns the number of messages 
(like I<login>) if successful and undef if the authentication failed. 
Remember that the connection is not closed if the authentication fails. 
You may issue a different authentication attempt. If you once are 
successfully authenticated, you cannot send the C<AUTH> command again.

=back

=head1 SEE ALSO

L<Net::POP3> and L<Net::Cmd>

=head1 AUTHOR

Alex Pleiner <alex@zeitform.de>, zeitform Internet Dienste.
Thanks to Graham Barr <gbarr@pobox.com> for Net::POP3.

=head1 COPYRIGHT

Copyright (c) 2003 zeitform Internet Dienste. All rights reserved.
This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut



