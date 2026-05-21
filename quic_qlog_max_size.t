#!/usr/bin/perl

# (C) Jakub Janecek

# Tests for quic_qlog_max_size directive.

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
	->has_daemon('openssl')->plan(2);

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

        quic_qlog          on;
        quic_qlog_path     qlog_limited;
        quic_qlog_max_size 1;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;

        quic_qlog      on;
        quic_qlog_path qlog_unlimited;

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
mkdir("$d/qlog_limited");
chmod(0777, "$d/qlog_limited");
mkdir("$d/qlog_unlimited");
chmod(0777, "$d/qlog_unlimited");

$t->run();

###############################################################################

my ($s, $sid);

# quic_qlog_max_size 1 - file is closed after the first buffer flush

$s = Test::Nginx::HTTP3->new(8980);
for (1..20) {
	$sid = $s->new_stream();
	$s->read(all => [{ sid => $sid, fin => 1 }]);
}
undef $s;

# no max_size - buffer flushes continue across all 20 requests

$s = Test::Nginx::HTTP3->new(8981);
for (1..20) {
	$sid = $s->new_stream();
	$s->read(all => [{ sid => $sid, fin => 1 }]);
}
undef $s;

my ($limited)   = glob("$d/qlog_limited/*.sqlog");
my ($unlimited) = glob("$d/qlog_unlimited/*.sqlog");

ok($limited && -s $limited, 'qlog max_size file created');
ok(-s $unlimited > -s $limited, 'qlog max_size limits growth');

###############################################################################
