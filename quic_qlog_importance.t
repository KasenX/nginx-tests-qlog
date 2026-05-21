#!/usr/bin/perl

# (C) Jakub Janecek

# Tests for quic_qlog_importance directive.
#
# Importance levels and what they log:
#   core  - transport:packet_sent/received, transport:parameters_set,
#           transport:version_information, recovery:metrics_updated, etc.
#   base  - all of the above plus connectivity:connection_started/closed,
#           recovery:parameters_set, security:key_updated/discarded, etc.
#   extra - identical to base (no extra-only events exist)

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
	->has_daemon('openssl')->plan(3);

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

        quic_qlog            on;
        quic_qlog_path       qlog_core;
        quic_qlog_importance core;

        location / { return 200; }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;

        quic_qlog            on;
        quic_qlog_path       qlog_base;
        quic_qlog_importance base;

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
mkdir("$d/qlog_core");
chmod(0777, "$d/qlog_core");
mkdir("$d/qlog_base");
chmod(0777, "$d/qlog_base");

$t->run();

###############################################################################

my ($s, $sid);

# generate enough traffic to fill the output buffer mid-connection so that
# events are flushed to disk without waiting for connection close

$s = Test::Nginx::HTTP3->new(8980);
for (1..20) {
	$sid = $s->new_stream();
	$s->read(all => [{ sid => $sid, fin => 1 }]);
}
undef $s;

$s = Test::Nginx::HTTP3->new(8981);
for (1..20) {
	$sid = $s->new_stream();
	$s->read(all => [{ sid => $sid, fin => 1 }]);
}
undef $s;

my ($core_file) = glob("$d/qlog_core/*.sqlog");
my ($base_file) = glob("$d/qlog_base/*.sqlog");

open my $fh, '<', $core_file or die "core qlog: $!";
my $core = do { local $/; <$fh> };
close $fh;

open $fh, '<', $base_file or die "base qlog: $!";
my $base = do { local $/; <$fh> };
close $fh;

# transport:version_information has no importance guard - present at all levels

like($core, qr/transport:version_information/, 'core: core event present');

# connectivity:connection_started has importance < BASE guard - absent at core

unlike($core, qr/connectivity:connection_started/, 'core: base event absent');

# same event must appear in the base-level log

like($base, qr/connectivity:connection_started/, 'base: base event present');

###############################################################################
