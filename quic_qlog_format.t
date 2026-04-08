#!/usr/bin/perl

# (C) Jakub Janecek

# Tests for qlog file format.

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

# generate enough traffic to fill the 8KB output buffer mid-connection so
# the file header is flushed to disk without waiting for connection close

my ($s, $sid);

$s = Test::Nginx::HTTP3->new(8980);
for (1..20) {
	$sid = $s->new_stream();
	$s->read(all => [{ sid => $sid, fin => 1 }]);
}
undef $s;

my ($file) = glob("$d/qlog/*.sqlog");

open my $fh, '<', $file or die "qlog file: $!";
my $content = do { local $/; <$fh> };
close $fh;

like($content, qr/\x1e\{"qlog_version":"0\.3","qlog_format":"JSON-SEQ"/,
	'qlog file starts with JSON-SEQ header');

like($content, qr/"vantage_point":\{"name":"nginx","type":"server"\}/,
	'qlog vantage point is nginx server');

###############################################################################
