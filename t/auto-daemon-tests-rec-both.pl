#!/usr/bin/perl

# pcap recordings with --record-both: a call's recording holds the media it
# received and, in addition, the media the media player sent to it, each packet with the
# addresses of its direction.

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use File::Temp qw(tempdir);
use POSIX;

my $recdir = tempdir(CLEANUP => 1);

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --recording-method=pcap --record-both),
		"--recording-dir=$recdir")
		or die;

# 200 ms of a 400 Hz tone, 8 kHz 16 bit mono
my $pcm = pack('s<*', map { int(12000 * sin($_ / 8000 * 2 * 3.14159265 * 400)) } 0 .. 1599);
my $wav_file = 'RIFF' . pack('V', 36 + length($pcm)) . 'WAVEfmt ' . pack('VvvVVvv', 16, 1, 1, 8000, 16000, 2, 16)
	. 'data' . pack('V', length($pcm)) . $pcm;

my ($sock_a, $sock_b, $port_a, $port_b, $resp);

($sock_a, $sock_b) = new_call([qw(198.51.100.1 3000)], [qw(198.51.100.3 3002)]);

($port_a) = offer('recorded call', { 'record call' => 'yes', replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('recorded call', { replace => ['origin'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 3002 RTP/AVP 8
c=IN IP4 198.51.100.3
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

# three packets from A, relayed to B: received media
for my $i (0 .. 2) {
	snd($sock_a, $port_b, rtp(8, 1000 + $i, 3000 + 160 * $i, 0x1234, "\x2a" x 160));
	rcv($sock_b, $port_a, rtpm(8, 1000 + $i, 3000 + 160 * $i, 0x1234, "\x2a" x 160));
}

# media played to A: sent media
$resp = rtpe_req('play media', 'play to the caller', { 'from-tag' => ft(), blob => $wav_file });
is $resp->{duration}, 200, 'media duration';
# (read off the socket as they are: what the tone encodes to is not this test's business)
my ($seq, $ssrc, @played);
for (1 .. 10) {
	alarm(2);
	$sock_a->recv(my $pkt, 2000) or die 'no played packet';
	alarm(0);
	my (undef, undef, $pseq, undef, $pssrc) = unpack('CCnNN', $pkt);
	$seq //= $pseq;
	$ssrc //= $pssrc;
	push @played, $pseq;
}
is_deeply \@played, [ map { ($seq + $_) & 0xffff } 0 .. 9 ], 'ten packets of played media reach the caller';

rtpe_req('delete', 'end of the call', { 'from-tag' => ft(), 'delete delay' => 0 });
sleep(1);

# the recording: raw IPv4 packets, as --recording-format=raw (the default) writes them
my ($pcap) = glob("$recdir/pcaps/*.pcap");
ok defined $pcap, 'the call has a recording';
open(my $fh, '<:raw', $pcap) or die "$pcap: $!";
read($fh, my $head, 24) == 24 or die 'short pcap';
my (@received, @sent);
while (read($fh, my $rec, 16) == 16) {
	my (undef, undef, $len) = unpack('VVV', $rec);
	read($fh, my $pkt, $len) == $len or last;
	my $ihl = (ord($pkt) & 0x0f) * 4;
	my $src = join('.', unpack('C4', substr($pkt, 12, 4)));
	my $dst = join('.', unpack('C4', substr($pkt, 16, 4)));
	my ($sport, $dport) = unpack('nn', substr($pkt, $ihl, 4));
	my ($b0, $b1, $rseq, $rts, $rssrc) = unpack('CCnNN', substr($pkt, $ihl + 8, 12));
	next if $b1 >= 192 && $b1 <= 223; # RTCP
	my $p = { src => "$src:$sport", dst => "$dst:$dport", pt => $b1 & 0x7f, seq => $rseq, ssrc => $rssrc,
		len => $len - $ihl - 8 - 12 };
	if ($src eq '203.0.113.1') { push @sent, $p } else { push @received, $p }
}
close($fh);

note("received: $_->{src} > $_->{dst} seq $_->{seq}") for @received;
note("sent: $_->{src} > $_->{dst} seq $_->{seq}") for @sent;
is scalar(@received), 3, 'the three packets that were received are in it';
is $received[0]{src}, '198.51.100.1:3000', 'from where they came';
is $received[0]{dst}, "203.0.113.1:$port_b", 'to the port they came in on';
is_deeply [ map { $_->{seq} } @received ], [ 1000, 1001, 1002 ], 'in order';

# what was sent: the three packets relayed to B, and the ten played to A
my @relayed = grep { $_->{dst} eq '198.51.100.3:3002' } @sent;
my @to_a = grep { $_->{dst} eq '198.51.100.1:3000' } @sent;
is scalar(@sent), 13, 'and so are the packets that were sent';
is_deeply [ map { $_->{seq} } @relayed ], [ 1000, 1001, 1002 ], 'the three relayed to the other side';
is $relayed[0]{src}, "203.0.113.1:$port_a", 'from the port they left on';
is scalar(@to_a), 10, 'and the ten the player sent';
is $to_a[0]{src}, "203.0.113.1:$port_b", 'from the port they left on';
is $to_a[0]{ssrc}, $ssrc, 'with the SSRC the caller got them under';
is_deeply [ map { $_->{seq} } @to_a ], [ map { ($seq + $_) & 0xffff } 0 .. 9 ], 'in the order they were sent';
is $to_a[0]{len}, 160, 'as the 20 ms of PCMA that went out';

done_testing();
