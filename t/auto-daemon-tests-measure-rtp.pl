#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;
use Data::Dumper;


autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 --measure-rtp --mos=LQ
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;


my $extended_tests = $ENV{RTPENGINE_MOS_TESTS};


my ($sock_a, $sock_b, $sock_c, $sock_d, $port_a, $port_b, $ssrc, $ssrc_b, $resp,
	$sock_ax, $sock_bx, $port_ax, $port_bx,
	$srtp_ctx_a, $srtp_ctx_b, $srtp_ctx_a_rev, $srtp_ctx_b_rev, $ufrag_a, $ufrag_b,
	@ret1, @ret2, @ret3, @ret4, $srtp_key_a, $srtp_key_b, $ts, $seq, $has_recv);



if ($extended_tests) {

($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7184)],
	[qw(198.51.100.1 7185)],
	[qw(198.51.100.3 7186)],
	[qw(198.51.100.3 7187)],
);

($port_a, $port_ax) = offer('unidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7184 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('unidirectional', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7186 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 0 } );
#print Dumper($resp);
#print Dumper($resp->{SSRC});
is($resp->{SSRC}{0x1234}{bytes}, 172, "0x1234 byte count");
is($resp->{SSRC}{0x6543}{bytes}, 172, "0x6543 byte count");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '43', "0x6543 MOS");
#print Dumper($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
#print Dumper($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{ft()}{medias}[0]{streams}[0]{SSRC});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{streams}[0]{SSRC});
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 1, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 52, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7160)],
	[qw(198.51.100.1 7161)],
	[qw(198.51.100.3 7162)],
	[qw(198.51.100.3 7163)],
);

($port_a, $port_ax) = offer('stats delete w/o from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7160 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('stats delete w/o from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7162 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 0 } );
#print Dumper($resp);
#print Dumper($resp->{SSRC});
is($resp->{SSRC}{0x1234}{bytes}, 172, "0x1234 byte count");
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '43', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{bytes}, 172, "0x6543 byte count");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '43', "0x6543 MOS");
#print Dumper($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
#print Dumper($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
#print Dumper($resp->{tags}{ft()}{medias}[0]{streams}[0]{SSRC});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
#print Dumper($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{streams}[0]{SSRC});
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7164)],
	[qw(198.51.100.1 7165)],
	[qw(198.51.100.3 7166)],
	[qw(198.51.100.3 7167)],
);

($port_a, $port_ax) = offer('stats delete w/ from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7164 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('stats delete w/ from-tag and w/o delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7166 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 0, 'from-tag' => ft() } );
#print Dumper($resp);
#print Dumper($resp->{SSRC});
is($resp->{SSRC}{0x1234}{bytes}, 172, "0x1234 byte count");
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '43', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{bytes}, 172, "0x6543 byte count");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '43', "0x6543 MOS");
#print Dumper($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
#print Dumper($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
#print Dumper($resp->{tags}{ft()}{medias}[0]{streams}[0]{SSRC});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
#print Dumper($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{streams}[0]{SSRC});
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7168)],
	[qw(198.51.100.1 7169)],
	[qw(198.51.100.3 7170)],
	[qw(198.51.100.3 7171)],
);

($port_a, $port_ax) = offer('stats delete w/o from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7168 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('stats delete w/o from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7170 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 1 } );
#print Dumper($resp);
#print Dumper($resp->{SSRC});
is($resp->{SSRC}{0x1234}{bytes}, 172, "0x1234 byte count");
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '43', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{bytes}, 172, "0x6543 byte count");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '43', "0x6543 MOS");
#print Dumper($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
#print Dumper($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
#print Dumper($resp->{tags}{ft()}{medias}[0]{streams}[0]{SSRC});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
#print Dumper($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{streams}[0]{SSRC});
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call(
	[qw(198.51.100.1 7172)],
	[qw(198.51.100.1 7173)],
	[qw(198.51.100.3 7174)],
	[qw(198.51.100.3 7175)],
);

($port_a, $port_ax) = offer('stats delete w/ from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 7172 RTP/AVP 8
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('stats delete w/ from-tag and w/ delete-delay', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 7174 RTP/AVP 8
c=IN IP4 198.51.100.3
a=rtpmap:8 PCMA/8000
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

snd($sock_a, $port_b, rtp( 8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
rcv($sock_b, $port_a, rtpm(8, 1000, 3000+160*0, 0x1234, "\x00" x 160));
snd($sock_b, $port_a, rtp( 8, 8000, 7000+160*0, 0x6543, "\x00" x 160));
rcv($sock_a, $port_b, rtpm(8, 8000, 7000+160*0, 0x6543, "\x00" x 160));

# RTCP
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_ax, $port_bx, "\x81\xc8\x00\x08\x00\x00\x12\x34\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x65\x43\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_bx, $port_ax, qr/^.*$/s);
#                              SR  LEN           SSRC       NTP1            NTP2            RTP            PACKETS         OCTETS           SSRC           LOST            SEQ            JITTER           LAST SR          DLSR
snd($sock_bx, $port_ax, "\x81\xc8\x00\x08\x00\x00\x65\x43\x11\x22\x33\x44\x11\x22\x33\x44\x11\x22\x33\x44\x00\x00\x00\x01\x00\x00\x00\xac\x00\x00\x12\x34\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x56\x78\x9a\xbc\x00\x00\x00\x20");
rcv($sock_ax, $port_bx, qr/^.*$/s);

$resp = rtpe_req('delete', 'delete', { 'delete delay' => 1, 'from-tag' => ft() } );
#print Dumper($resp);
#print Dumper($resp->{SSRC});
is($resp->{SSRC}{0x1234}{bytes}, 172, "0x1234 byte count");
is($resp->{SSRC}{0x1234}{'highest MOS'}{MOS}, '43', "0x1234 MOS");
is($resp->{SSRC}{0x6543}{bytes}, 172, "0x6543 byte count");
is($resp->{SSRC}{0x6543}{'highest MOS'}{MOS}, '43', "0x6543 MOS");
#print Dumper($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x6543, 'egress SSRC');
#print Dumper($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'});
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x1234, 'ingress SSRC');
is($resp->{tags}{ft()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
#print Dumper($resp->{tags}{ft()}{medias}[0]{streams}[0]{SSRC});
#print Dumper($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'});
is($resp->{tags}{tt()}{medias}[0]{'egress SSRCs'}[0]{SSRC}, 0x1234, 'egress SSRC');
#print Dumper($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'});
#print Dumper($resp->{tags}{tt()}{medias}[0]{streams}[0]{SSRC});
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{SSRC}, 0x6543, 'ingress SSRC');
is($resp->{tags}{tt()}{medias}[0]{'ingress SSRCs'}[0]{'highest MOS'}{MOS}, '43', 'ingress SSRC MOS');
is($resp->{totals}{RTP}{packets}, 2, 'RTP packet count');
is($resp->{totals}{RTP}{bytes}, 344, 'RTP octet count');
is($resp->{totals}{RTCP}{packets}, 2, 'RTCP packet count');
is($resp->{totals}{RTCP}{bytes}, 104, 'RTCP octet count');




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3000)], [qw(198.51.100.23 3001)],
							[qw(198.51.100.23 3002)], [qw(198.51.100.23 3003)]);

($port_a, $port_ax) = offer('MOS basic', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3000 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS basic', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3002 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 15 seconds = 750 packets
for my $iter (0 .. 750) {
	snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
	snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	Time::HiRes::usleep(20000);
}

$resp = rtpe_req('delete', 'MOS basic', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 3, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, 43, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
is $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, 0, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 3, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, 43, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
is $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, 0, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3004)], [qw(198.51.100.23 3005)],
							[qw(198.51.100.23 3006)], [qw(198.51.100.23 3007)]);

($port_a, $port_ax) = offer('MOS PL', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3004 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS PL', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3006 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 15 seconds = 750 packets, drop every 20th (5% PL)
for my $iter (0 .. 750) {
	if (($iter % 20) != 19) {
		snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
		rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	}
	Time::HiRes::usleep(20000);
}

$resp = rtpe_req('delete', 'MOS PL', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '>=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '<=', 4, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 35, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 36, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 0, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '>=', 3, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '<=', 4, 'metric matches';




($sock_a, $sock_ax, $sock_b, $sock_bx) = new_call([qw(198.51.100.23 3008)], [qw(198.51.100.23 3009)],
							[qw(198.51.100.23 3010)], [qw(198.51.100.23 3011)]);

($port_a, $port_ax) = offer('MOS very degraded', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3008 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

($port_b, $port_bx) = answer('MOS very degraded', { flags => ['generate RTCP'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
c=IN IP4 198.51.100.23
t=0 0
m=audio 3010 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.23
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP


# run 20 seconds = 1000 packets, drop every 10th (10% PL), add random jitter
srand(123456);
for my $iter (0 .. 1000) {
	if (($iter % 10) != 9) {
		snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		rcv($sock_b, $port_a, rtpm(0, 1000 + $iter, 3000 + 160 * $iter, 0x1234567, "\x00" x 160));
		snd($sock_b, $port_a, rtp(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
		rcv($sock_a, $port_b, rtpm(0, 2000 + $iter, 4000 + 160 * $iter, 0x7654321, "\x00" x 160));
	}
	Time::HiRes::usleep(20000 + rand(40000) - 20000);
}

$resp = rtpe_req('delete', 'MOS very degraded', { });

cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{samples}, '<=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '>=', 27, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{MOS}, '<=', 28, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '>=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{jitter}, '<=', 12, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '>=', 8, 'metric matches';
cmp_ok $resp->{SSRC}{0x1234567}{'average MOS'}{'packet loss'}, '<=', 9, 'metric matches';

cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '>=', 1, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{samples}, '<=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '>=', 27, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{MOS}, '<=', 28, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '>=', 4, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{jitter}, '<=', 12, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '>=', 8, 'metric matches';
cmp_ok $resp->{SSRC}{0x7654321}{'average MOS'}{'packet loss'}, '<=', 9, 'metric matches';



}


# received media is measured (jitter, sequence gaps) even while it is blocked:
# block-media plus play-media is how a media stream is terminated locally

# relayed as it is, and through a transcoder (which counts loss in its sequencer)
for my $transcode (0, 1) {

($sock_a, $sock_b) = new_call([qw(198.51.100.43 3100)], [qw(198.51.100.43 3102)]);

my $offer_out = $transcode
	? "m=audio PORT RTP/AVP 0 8 101\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\na=rtpmap:101 telephone-event/8000\n"
	: "m=audio PORT RTP/AVP 0 101\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\na=rtpmap:101 telephone-event/8000\n";
my $answer_pt = $transcode ? 8 : 0;

($port_a) = offer('measure blocked media', { $transcode ? (codec => { transcode => ['PCMA'] }) : () }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3100 RTP/AVP 0 101
a=rtpmap:101 telephone-event/8000
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
${offer_out}a=sendrecv
a=rtcp:PORT
SDP

($port_b) = answer('measure blocked media', { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3102 RTP/AVP $answer_pt 101
a=rtpmap:101 telephone-event/8000
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

if (!$transcode) {
	snd($sock_a, $port_b, rtp(0, 1000, 3000, 0x2345678, "\x00" x 160));
	rcv($sock_b, $port_a, rtpm(0, 1000, 3000, 0x2345678, "\x00" x 160));
}

rtpe_req('block media', 'measure blocked media', { });

my $intf_ingress = sub {
	my $r = rtpe_req('statistics', 'measure blocked media stats', { });
	my ($intf) = grep { $_->{address} eq '203.0.113.1' } @{$r->{statistics}{interfaces}};
	return $intf->{ingress};
};

my $before = $intf_ingress->();

# 2.4 seconds of packets spaced 10 and 30 ms in turn (a steady 20 ms of jitter on every
# packet), every tenth one missing
for my $iter (1 .. 120) {
	if (($iter >= 41 && $iter <= 46) || ($iter >= 91 && $iter <= 93)) {
		# two DTMF events in between: they share the sequence numbers and are no gaps,
		# and the audio between them is not lost either
		my $start = $iter < 90 ? 41 : 91;
		snd($sock_a, $port_b, rtp(101, 1000 + $iter, 3000 + 160 * $start, 0x2345678,
				"\x05\x0a" . pack('n', 160 * ($iter - $start + 1))));
	}
	elsif ($iter % 10) {
		snd($sock_a, $port_b, rtp(0, 1000 + $iter, 3000 + 160 * $iter, 0x2345678, "\x00" x 160));
	}
	Time::HiRes::usleep($iter % 2 ? 10000 : 30000);
}
# (nothing of the audio is relayed; the DTMF event is, as block-media lets events through)
# the samples are collected by the once-per-second call timer
Time::HiRes::sleep(1.2);

my $after = $intf_ingress->();
my $samples = $after->{jitter_samples} - $before->{jitter_samples};
cmp_ok $samples, '>=', 1, 'blocked media: jitter was sampled';
my $jitter = ($after->{jitter_average_ms} * $after->{jitter_samples}
		- $before->{jitter_average_ms} * $before->{jitter_samples}) / ($samples || 1);
cmp_ok $jitter, '>=', 5, 'blocked media: jitter is measured';
cmp_ok $jitter, '<=', 25, 'blocked media: jitter is in milliseconds';
# a gap counts as lost once it has left the 32-packet window, so the last ones are not in yet
cmp_ok $after->{packets_lost} - $before->{packets_lost}, '>=', 6, 'blocked media: lost packets are counted';
cmp_ok $after->{packets_lost} - $before->{packets_lost}, '<=', 12, 'blocked media: lost packets are counted once';
diag("blocked media: jitter $jitter ms over $samples samples, lost " . ($after->{packets_lost} - $before->{packets_lost}));

rtpe_req('delete', 'measure blocked media', { });

}


# What a received stream lost is counted once: every sequence number that is missing from
# it, whatever the stream's outputs are (relayed as it is, behind a transcoder, blocked) and
# whichever of them come and go while it runs. Each case below is one such stream: packets
# go missing before and right after every change, and in the end the count is the number of
# packets that were left out, exactly.

sub loss_case {
	my ($name, $tc_call, $steps, $mode) = @_;
	$name = "loss counted once - $name";
	$mode //= '';

	my ($s_a, $s_b, $s_c) =
		new_call([qw(198.51.100.43 3110)], [qw(198.51.100.43 3112)], [qw(198.51.100.43 3114)]);

	my $offer_out = $tc_call
		? "m=audio PORT RTP/AVP 0 8\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\n"
		: "m=audio PORT RTP/AVP 0\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\n";
	my $answer_pt = $tc_call ? 8 : 0;

	my $p_b;
	if ($mode eq 'publish') {
	# a published stream: it has no output at all until somebody subscribes to it
	($p_b) = publish($name, { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3110 RTP/AVP 0
a=sendonly
-----------------------------------------
v=0
o=- SDP_VERSION IN IP4 203.0.113.1
s=RTPE_VERSION
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=recvonly
a=rtcp:PORT
SDP
	}
	else {
	offer($name, { $tc_call ? (codec => { transcode => ['PCMA'] }) : (),
			$mode eq 'blackhole' ? ('media echo' => 'blackhole') : () }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3110 RTP/AVP 0
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
${offer_out}a=sendrecv
a=rtcp:PORT
SDP

	($p_b) = answer($name, { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3112 RTP/AVP $answer_pt
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

	}

	my $intf_lost = sub {
		my $r = rtpe_req('statistics', "$name stats", { });
		my ($intf) = grep { $_->{address} eq '203.0.113.1' } @{$r->{statistics}{interfaces}};
		return $intf->{ingress}{packets_lost};
	};
	my $before = $intf_lost->();

	my ($seq, $missing, $sub_tag) = (1000, 0);
	my %c;
	# the next $n sequence numbers, without those at the given places among them
	$c{send} = sub {
		my ($n, @drop) = @_;
		my %drop = map { $_ => 1 } @drop;
		for my $i (0 .. $n - 1) {
			if ($drop{$i}) {
				$missing++;
			}
			else {
				snd($s_a, $p_b, rtp(0, ($seq + $i) & 0xffff, 3000 + 160 * ($seq + $i - 1000),
						0x2345679, "\x00" x 160));
				Time::HiRes::usleep(1500);
			}
		}
		$seq += $n;
	};
	# a second output: a subscriber the stream is relayed to as it is, or one behind a transcoder
	$c{subscribe} = sub {
		my ($transcoded) = @_;
		my $sdp_out = $transcoded
			? "m=audio PORT RTP/AVP 0 8\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\n"
			: "m=audio PORT RTP/AVP 0\nc=IN IP4 203.0.113.1\na=rtpmap:0 PCMU/8000\n";
		my $sub_pt = $transcoded ? 8 : 0;
		(undef, $sub_tag) = subscribe_request($name,
			{ 'from-tag' => ft(), $transcoded ? (codec => { transcode => ['PCMA'] }) : () }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
${sdp_out}a=sendonly
a=rtcp:PORT
SDP
		subscribe_answer($name, { 'from-tag' => ft(), 'to-tag' => $sub_tag,
				$transcoded ? (flags => ['allow transcoding']) : () }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
m=audio 3114 RTP/AVP $sub_pt
c=IN IP4 198.51.100.43
a=recvonly
SDP
	};
	$c{unsubscribe} = sub {
		rtpe_req('unsubscribe', $name, { 'from-tag' => ft(), 'to-tag' => $sub_tag });
	};
	# 'call': the call's own output, 'subscriber': the second one, 'all': the stream as a whole
	my $which = sub {
		my ($what) = @_;
		return { } if $what eq 'all';
		return { 'from-tag' => ft(), flags => ['directional'],
			all => $what eq 'call' ? 'offer-answer' : 'except-offer-answer' };
	};
	$c{block} = sub { rtpe_req('block media', $name, $which->($_[0])) };
	$c{unblock} = sub { rtpe_req('unblock media', $name, $which->($_[0])) };

	$steps->(\%c);

	# (a packet counts as lost once the stream is 32 packets past it)
	$c{send}->(40);

	is $intf_lost->() - $before, $missing, "$name: each of the $missing lost packets is counted once";

	rtpe_req('delete', $name, { });
}

# one output, relayed or transcoded: single packets, and more in a row than the window holds
for my $tc (0, 1) {
	my $how = $tc ? 'transcoded' : 'relayed';
	loss_case("$how, a burst", $tc, sub {
		my ($c) = @_;
		$c->{send}->(40, 10, 20);
		$c->{send}->(100, 20 .. 69);
		$c->{send}->(20, 5);
	});
	# blocked and unblocked again, with packets missing right before and after either
	loss_case("$how, blocked and unblocked", $tc, sub {
		my ($c) = @_;
		$c->{send}->(40, 10, 37);
		$c->{block}->('all');
		$c->{send}->(40, 2, 20, 38);
		$c->{unblock}->('all');
		$c->{send}->(40, 1, 20);
	});
	# nothing for more than a second, then on: nobody takes anything over, nothing is lost
	loss_case("$how, a pause", $tc, sub {
		my ($c) = @_;
		$c->{send}->(40, 10, 38);
		Time::HiRes::sleep(1.2);
		$c->{send}->(40, 1);
	});
}

# a second output comes in while the stream runs, and leaves again: every combination of
# relayed and transcoded
for my $tc_call (0, 1) {
	for my $tc_sub (0, 1) {
		my $how = ($tc_call ? 'transcoded' : 'relayed') . ' plus a ' . ($tc_sub ? 'transcoded' : 'relayed') . ' subscriber';
		loss_case("$how, subscribed and unsubscribed", $tc_call, sub {
			my ($c) = @_;
			$c->{send}->(40, 10, 38);
			$c->{subscribe}->($tc_sub);
			$c->{send}->(40, 1, 20, 38);
			$c->{unsubscribe}->();
			$c->{send}->(40, 1, 20);
		});
		# either of the two blocked while the other goes on, and unblocked again
		for my $blocked ('call', 'subscriber') {
			loss_case("$how, the $blocked blocked and unblocked", $tc_call, sub {
				my ($c) = @_;
				$c->{subscribe}->($tc_sub);
				$c->{send}->(40, 10, 38);
				$c->{block}->($blocked);
				$c->{send}->(40, 1, 20, 38);
				$c->{unblock}->($blocked);
				$c->{send}->(40, 1, 20);
			});
		}
	}
}

# the output the stream is relayed to leaves while a transcoded one stays, and in the second
# after that more packets go missing, one by one, than the window holds
loss_case('transcoded plus a relayed subscriber, many lost right after it leaves', 1, sub {
	my ($c) = @_;
	$c->{subscribe}->(0);
	$c->{send}->(40, 10, 38);
	$c->{unsubscribe}->();
	$c->{send}->(80, map { 2 * $_ + 1 } 0 .. 39);
	Time::HiRes::sleep(1.2);
	$c->{send}->(20, 5);
});

# the transcoded output is blocked and unblocked while the stream is also relayed, and then
# the one it is relayed to leaves: the stretch that was blocked is not taken for lost
loss_case('transcoded plus a relayed subscriber, blocked, unblocked, then the relayed one leaves', 1, sub {
	my ($c) = @_;
	$c->{subscribe}->(0);
	$c->{send}->(40, 10);
	$c->{block}->('call');
	$c->{send}->(20, 5);
	$c->{unblock}->('call');
	$c->{send}->(10, 8);
	$c->{unsubscribe}->();
	$c->{send}->(40, 1, 20);
	Time::HiRes::sleep(1.2);
	$c->{send}->(20, 5);
});

# a published stream is received whether anybody is subscribed to it or not: what comes in
# while it has no output is neither missed nor taken for lost when a subscriber comes back
for my $tc_sub (0, 1) {
	loss_case('published, the ' . ($tc_sub ? 'transcoded' : 'relayed') . ' subscriber leaves and comes back', 0, sub {
		my ($c) = @_;
		$c->{send}->(40, 10, 38);
		$c->{subscribe}->($tc_sub);
		$c->{send}->(40, 1, 38);
		$c->{unsubscribe}->();
		$c->{send}->(40, 1, 20, 38);
		$c->{subscribe}->($tc_sub);
		$c->{send}->(40, 1);
	}, 'publish');
}

# ... and so is one that is received only to be thrown away
loss_case('thrown away', 0, sub {
	my ($c) = @_;
	$c->{send}->(40, 10, 38);
	$c->{send}->(40, 1, 20);
}, 'blackhole');


# Jitter: every received packet is one sample of it.

sub jitter_case {
	my ($name, $steps) = @_;
	$name = "jitter - $name";

	my ($s_a, $s_b) = new_call([qw(198.51.100.43 3130)], [qw(198.51.100.43 3132)]);

	offer($name, { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3130 RTP/AVP 0 101
a=rtpmap:101 telephone-event/8000
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

	my ($p_b) = answer($name, { }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
c=IN IP4 198.51.100.43
t=0 0
m=audio 3132 RTP/AVP 0 101
a=rtpmap:101 telephone-event/8000
-----------------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.100.43
s=tester
t=0 0
m=audio PORT RTP/AVP 0 101
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=rtcp:PORT
SDP

	# (the last sample of the stream before this one is taken first: the interface's
	# figures are of all its streams)
	Time::HiRes::sleep(1.2);

	my %c;
	my ($seq, $ts, $last) = (1000, 3000, Time::HiRes::time());
	# One packet now. Its timestamp is that many packets of 20 ms after the one before
	# (none: the same timestamp again), or 'now': as much later as it really is since the
	# timestamp last moved on.
	$c{snd} = sub {
		my ($pt, $payload, $steps) = @_;
		$steps //= 1;
		my $now = Time::HiRes::time();
		$ts += $steps eq 'now' ? int(($now - $last) * 8000) : 160 * $steps;
		$last = $now if $steps; # (when the timestamp last moved on)
		snd($s_a, $p_b, rtp($pt, $seq++, $ts, 0x234567b, $payload));
	};
	# what the samples taken over the next good second average to, in ms
	# (they are taken by the once-per-second call timer)
	$c{sampled} = sub {
		my $get = sub {
			my $r = rtpe_req('statistics', "$name stats", { });
			my ($intf) = grep { $_->{address} eq '203.0.113.1' } @{$r->{statistics}{interfaces}};
			return $intf->{ingress};
		};
		my $before = $get->();
		$_[0]->();
		Time::HiRes::sleep(1.2);
		my $after = $get->();
		my $n = $after->{jitter_samples} - $before->{jitter_samples};
		cmp_ok $n, '>=', 1, "$name: sampled";
		return ($after->{jitter_average_ms} * $after->{jitter_samples}
				- $before->{jitter_average_ms} * $before->{jitter_samples}) / ($n || 1);
	};
	# a second of packets 10 and 30 ms apart in turn: 10 ms of jitter on each
	$c{jittery} = sub {
		for my $i (1 .. 50) {
			$c{snd}->(0, "\x00" x 160);
			Time::HiRes::usleep($i % 2 ? 10000 : 30000);
		}
	};

	$steps->(\%c);

	rtpe_req('delete', $name, { });
}

# packets that share a timestamp and come in together (the packets of one video frame) are
# samples like any other: with them the estimate comes down, as nothing about them jitters
jitter_case('packets with one timestamp', sub {
	my ($c) = @_;
	my $j = $c->{sampled}->($c->{jittery});
	cmp_ok $j, '>=', 5, 'jitter - packets with one timestamp: there is jitter before them';
	diag("jitter before the packets with one timestamp: $j ms");
	$j = $c->{sampled}->(sub {
		$c->{snd}->(0, "\x00" x 160, 'now');
		for (1 .. 80) {
			# (one after the other, just not faster than they are taken)
			Time::HiRes::usleep(300);
			$c->{snd}->(0, "\x00" x 160, 0);
		}
	});
	cmp_ok $j, '<=', 3, 'jitter - packets with one timestamp: and next to none after them';
	diag("jitter after 80 packets with one timestamp: $j ms");
});

# the packets of a telephone event repeat one timestamp while time goes on: that is no jitter
jitter_case('a telephone event', sub {
	my ($c) = @_;
	my $j = $c->{sampled}->(sub {
		for (1 .. 50) {
			$c->{snd}->(0, "\x00" x 160);
			Time::HiRes::usleep(20000);
		}
	});
	# (what a steady stream measures here is how exactly this test sleeps: a few ms)
	cmp_ok $j, '<=', 6, 'jitter - a telephone event: a steady stream has little';
	diag("jitter of a steady stream: $j ms");
	$j = $c->{sampled}->(sub {
		$c->{snd}->(0, "\x00" x 160, 'now');
		Time::HiRes::usleep(20000);
		$c->{snd}->(101, "\x05\x0a\x00\xa0");
		for my $i (2 .. 25) {
			Time::HiRes::usleep(20000);
			$c->{snd}->(101, "\x05\x0a" . pack('n', 160 * $i), 0);
		}
		for my $i (1 .. 3) {
			Time::HiRes::usleep(20000);
			$c->{snd}->(0, "\x00" x 160, $i == 1 ? 'now' : 1);
		}
	});
	# (25 packets taken as 20 ms late each would be some 15 ms of it)
	cmp_ok $j, '<=', 6, 'jitter - a telephone event: and no more with an event in it';
	diag("jitter of a steady stream with a telephone event: $j ms");
});



#done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
done_testing();
