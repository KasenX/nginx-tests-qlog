#!/usr/bin/perl

# (C) Jakub Janecek

# Tests for quic_qlog_allow directive.

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
	->has_daemon('openssl')->plan(4);

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

        quic_qlog        on;
        quic_qlog_path   %%TESTDIR%%/qlog;
        quic_qlog_allow  127.0.0.1;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;

        quic_qlog        on;
        quic_qlog_path   %%TESTDIR%%/qlog;
        quic_qlog_allow  10.0.0.0/8;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8982_UDP%% quic;
        server_name  localhost;

        quic_qlog        on;
        quic_qlog_path   %%TESTDIR%%/qlog;
        quic_qlog_allow  10.0.0.0/8;
        quic_qlog_allow  127.0.0.0/8;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8983_UDP%% quic;
        server_name  localhost;

        quic_qlog        on;
        quic_qlog_path   %%TESTDIR%%/qlog;

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
mkdir("$d/qlog");
chmod(0777, "$d/qlog");

$t->run();

###############################################################################

my ($s, $sid, $frames, @files);

# quic_qlog_allow with matching exact IP

$s = Test::Nginx::HTTP3->new(8980);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

@files = glob("$d/qlog/*.sqlog");
is(scalar @files, 1, 'qlog allow exact IP match');

# quic_qlog_allow with non-matching network

$s = Test::Nginx::HTTP3->new(8981);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

@files = glob("$d/qlog/*.sqlog");
is(scalar @files, 1, 'qlog allow no match');

# quic_qlog_allow multiple entries, last entry matches

$s = Test::Nginx::HTTP3->new(8982);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

@files = glob("$d/qlog/*.sqlog");
is(scalar @files, 2, 'qlog allow CIDR match');

# no quic_qlog_allow, all connections logged

$s = Test::Nginx::HTTP3->new(8983);
$sid = $s->new_stream();
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

@files = glob("$d/qlog/*.sqlog");
is(scalar @files, 3, 'qlog allow unrestricted');

###############################################################################
