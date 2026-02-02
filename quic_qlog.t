#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for QUIC qlog output.

###############################################################################

use warnings;
use strict;

use Test::More;
use JSON::PP qw/decode_json/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
user root;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        listen       127.0.0.1:8081;
        server_name  localhost;

        quic_qlog on;
        quic_qlog_path %%TESTDIR%%/qlog;

        location / {
            add_header X-Qlog-Test ok;
            return 200;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();
mkdir "$d/qlog";

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();

###############################################################################

my $s = Test::Nginx::HTTP3->new();
my $sid = $s->new_stream({ path => '/' });
my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'http3 response');

my $qlog = wait_for_qlog("$d/qlog");
ok($qlog && -s $qlog, 'qlog file created');

my $data = read_file($qlog);
my $events = parse_qlog_events($data);
ok(@$events >= 3, 'qlog events parsed');
is($events->[0]->{qlog_version}, '0.3', 'qlog version');
is($events->[0]->{qlog_format}, 'JSON-SEQ', 'qlog format');
is($events->[0]->{trace}->{common_fields}->{time_format}, 'relative',
	'time format');
ok($events->[0]->{trace}->{common_fields}->{reference_time},
	'reference time');
is($events->[0]->{trace}->{vantage_point}->{name}, 'nginx',
	'vantage point name');
is($events->[0]->{trace}->{vantage_point}->{type}, 'server',
	'vantage point type');
ok(event_exists($events, 'transport:parameters_set', { owner => 'local' }),
	'local transport parameters');
ok(event_exists($events, 'transport:parameters_set', { owner => 'remote' }),
	'remote transport parameters');
ok(event_exists($events, 'transport:packet_sent'), 'packet sent');
ok(event_exists($events, 'transport:packet_received'), 'packet received');

###############################################################################

sub wait_for_qlog {
	my ($dir) = @_;

	for (1 .. 50) {
		my @files = glob("$dir/*.sqlog");
		return $files[0] if @files;
		select undef, undef, undef, 0.1;
	}

	return;
}

sub read_file {
	my ($file) = @_;

	open my $fh, '<', $file or return '';
	binmode $fh;
	local $/;
	my $data = <$fh>;
	close $fh;

	return $data;
}

sub parse_qlog_events {
	my ($data) = @_;

	my @events;

	for my $chunk (split /\x1e/, $data) {
		$chunk =~ s/^\s+|\s+$//g;
		next unless length $chunk;

		my $obj = eval { decode_json($chunk) };
		next unless $obj;

		push @events, $obj;
	}

	return \@events;
}

sub event_exists {
	my ($events, $name, $match) = @_;

	for my $event (@$events) {
		next unless $event->{name} && $event->{name} eq $name;
		return 1 if !$match;

		my $data = $event->{data} || {};
		my $ok = 1;

		for my $key (keys %$match) {
			$ok &&= defined $data->{$key} && $data->{$key} eq $match->{$key};
		}

		return 1 if $ok;
	}

	return 0;
}

###############################################################################
