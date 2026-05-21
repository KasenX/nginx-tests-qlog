#!/usr/bin/perl

# (C) Jakub Janecek

# Tests for qlog file creation error paths.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx quic_qlog_module/)
	->has_daemon('openssl')->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;

        quic_qlog      on;
        quic_qlog_path %%TESTDIR%%/qlog_nowrite;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;

        quic_qlog      on;
        quic_qlog_path %%TESTDIR%%/qlog_file;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8982_UDP%% quic;
        server_name  localhost;

        quic_qlog      on;
        quic_qlog_path %%TESTDIR%%/qlog_missing/subdir;

        location / { return 200; }
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

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

chmod(0711, $d);
mkdir("$d/qlog_nowrite");
chmod(0555, "$d/qlog_nowrite");
$t->write_file('qlog_file', "not a directory\n");

$t->run();

###############################################################################

my ($s, $sid, $frames, $frame, $log);

$s = Test::Nginx::HTTP3->new(8980);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'qlog unwritable path still serves request');

ok(!glob("$d/qlog_nowrite/*.sqlog"), 'qlog unwritable path creates no file');

$s = Test::Nginx::HTTP3->new(8981);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'qlog file path still serves request');

ok(-f "$d/qlog_file", 'qlog file path remains a regular file');

$s = Test::Nginx::HTTP3->new(8982);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'qlog missing path still serves request');

ok(!-e "$d/qlog_missing", 'qlog missing path is not created implicitly');

open my $fh, '<', "$d/error.log" or die "error.log: $!";
$log = do { local $/; <$fh> };
close $fh;

like($log, qr{\Qopen() "$d/qlog_nowrite/\E.*Permission denied},
	'qlog logs unwritable directory open failure');

like($log, qr{\Qopen() "$d/qlog_file/\E.*Not a directory},
	'qlog logs non-directory path open failure');

like($log, qr{\Qopen() "$d/qlog_missing/subdir/\E.*No such file or directory},
	'qlog logs missing directory open failure');

is(scalar(() = $log =~ /quic qlog init failed, continuing without qlog/g), 3,
	'qlog init failure falls back cleanly for each connection');

###############################################################################
