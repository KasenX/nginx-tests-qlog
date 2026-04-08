#!/usr/bin/perl

# (C) Jakub Janecek

# Tests that each QUIC connection produces its own qlog file.

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
	->has_daemon('openssl')->plan(1);

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
        quic_qlog_path qlog;

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

# each connection gets its own {cid_hex}.sqlog file created at connection start

my ($s, $sid);

$s = Test::Nginx::HTTP3->new(8980);
$sid = $s->new_stream();
$s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

$s = Test::Nginx::HTTP3->new(8980);
$sid = $s->new_stream();
$s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

$s = Test::Nginx::HTTP3->new(8980);
$sid = $s->new_stream();
$s->read(all => [{ sid => $sid, fin => 1 }]);
undef $s;

my @files = glob("$d/qlog/*.sqlog");
is(scalar @files, 3, '3 connections create 3 qlog files');

###############################################################################
