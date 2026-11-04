#!/bin/sh
# INV-590: evidence must bind real paths/bytes and refuse drift, not invent cost.
set -eu
exec perl - "$0" "$@" <<'PERL'
use strict;
use warnings;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP;
use Test::More;

my $root = abs_path(dirname(shift @ARGV) . '/../../..');
die "usage: BASM=/path/to/basm sh tests/lab_test.sh\n" if @ARGV;
my $lab = "$root/toolchain/BearBasm/lab";
my $script = "$lab/evidence.pl";
my $tmp = tempdir('basm-lab-XXXXXX', TMPDIR => 1, CLEANUP => !$ENV{LAB_KEEP});
my $seq = 0;
sub read_bytes {
    open my $f, '<:raw', $_[0] or die "read $_[0]: $!\n";
    local $/;
    return scalar(<$f>) // '';
}
sub write_bytes {
    open my $f, '>:raw', $_[0] or die "write $_[0]: $!\n";
    print {$f} $_[1] or die "write: $!\n";
    close $f or die "close: $!\n";
}
sub run {
    my @argv = @_;
    my $n = ++$seq;
    my $pid = fork();
    die "fork: $!\n" unless defined $pid;
    if (!$pid) {
        open STDOUT, '>', "$tmp/$n.out" or die $!;
        open STDERR, '>', "$tmp/$n.err" or die $!;
        exec { $argv[0] } @argv;
        die "exec $argv[0]: $!\n";
    }
    waitpid($pid, 0) == $pid or die "waitpid: $!\n";
    return ($?, read_bytes("$tmp/$n.out"), read_bytes("$tmp/$n.err"));
}
my ($rc, $out, $err) = run($^X, $script, '--help');
is($rc, 0, 'collector help needs no artifacts or basm');
like($out, qr/Usage:.*--basm/s, 'help describes explicit basm path');
BAIL_OUT('collector help unavailable') if $rc;

my $inventory = decode_json(read_bytes("$lab/inventory-v1.json"));
my $basm = abs_path($ENV{BASM} // "$root/toolchain/BearBasm/basm");
BAIL_OUT('missing caller basm') unless defined $basm && -f $basm && -x $basm;
my $basm_sha = sha256_hex(read_bytes($basm));
my @artifacts;
my @commands;
local $ENV{SOURCE_DATE_EPOCH} = '0';
for my $fixture (@{$inventory->{workload}->{fixtures}}) {
    my $source = "$root/$fixture->{path}";
    is(sha256_hex(read_bytes($source)), $fixture->{sha256}, "$fixture->{id}: frozen source")
        or BAIL_OUT('fixed workload checksum drift');
    my $obj = "$tmp/$fixture->{id}.o";
    my $proof = "$obj.basmproof";
    my @argv = ($basm, '-f', 'elf64', '-o', $obj, '--emit-attestation', $proof, $source);
    push @commands, \@argv;
    ($rc, $out, $err) = run(@argv);
    is($rc, 0, "$fixture->{id}: assemble only, serial") or diag($err);
    BAIL_OUT('fixed workload assembly failed') if $rc;
    push @artifacts, '--artifact', "$fixture->{id}=$obj", '--artifact', "$fixture->{id}-proof=$proof";
}
write_bytes("$tmp/commands.json", JSON::PP->new->canonical->pretty->encode(\@commands));
my @args = ('--repo-root', $root, '--basm', $basm, @artifacts);
($rc, $out, $err) = run($^X, $script, @args);
is($rc, 0, 'collect real artifacts') or diag($err);
BAIL_OUT('cannot collect manifest') if $rc;
write_bytes("$tmp/evidence.json", $out);
my $manifest = decode_json($out);
my ($rc2, $out2, $err2) = run($^X, $script, @args);
is($rc2, 0, 'second collection succeeds') or diag($err2);
is($out2, $out, 'identical inputs and paths give byte-identical manifest');
unlike($out, qr/"(?:timestamp|created_at|mtime|ctime|wall_time|elapsed|pid)"\s*:/,
       'manifest contains no wall clock or process identity');
is($manifest->{evidence_kind}, 'IDENTITY_ONLY', 'no measurement claim');
ok(!defined $manifest->{measurements}, 'baseline remains unmeasured');
is($manifest->{linkage}, 'UNPROVEN', 'artifact hashes are not provider reachability');
is($manifest->{tools}->{basm}->{sha256}, sha256_hex(read_bytes($basm)), 'exact basm bytes');
is($manifest->{workload}->{id}, 'ic02-assembly-v1', 'versioned corpus ID');
is(scalar @{$manifest->{workload}->{fixtures}}, 3, 'all fixed corpus IDs retained');
is(scalar keys %{$manifest->{artifacts}}, 6, 'all object and proof identities retained');
for (my $i = 1; $i < @artifacts; $i += 2) {
    my ($id, $path) = split /=/, $artifacts[$i], 2;
    is_deeply($manifest->{artifacts}->{$id},
              {path => $path, resolved_path => abs_path($path),
               bytes => length(read_bytes($path)), sha256 => sha256_hex(read_bytes($path))},
              "$id: exact artifact bytes and paths");
}
is_deeply([map { $_->{partition} } @{$manifest->{workload}->{fixtures}}],
          ['tuning', 'tuning', 'validation'], 'held-out partition is retained');
is($manifest->{budgets}->{ratification}, 'PENDING', 'new budgets are not ratified');
is($manifest->{lane}->{status}, 'UNSPECIFIED', 'compiler/runtime lane is not guessed');

sub refuses {
    my ($name, $pattern, @options) = @_;
    my ($status, $stdout, $stderr) = run($^X, $script, @options);
    ok($status != 0, "$name: refused");
    is($stdout, '', "$name: no partial manifest");
    like($stderr, $pattern, "$name: actionable diagnostic");
}
refuses('missing basm', qr/missing.*tool.*basm/i, '--basm', "$tmp/absent", @artifacts);
refuses('missing artifact', qr/missing.*artifact/i, @args, '--artifact', "missing=$tmp/absent");
refuses('missing auxiliary tool', qr/missing.*tool/i, @args, '--tool', "compiler=$tmp/absent");
refuses('no artifacts', qr/at least one --artifact/, '--basm', $basm);
refuses('no command execution CLI', qr/Unknown option|usage/i, @args, '--run', '/bin/false');
refuses('duplicate identity', qr/duplicate artifact/, @args, '--artifact', "$inventory->{workload}->{fixtures}->[0]->{id}=$basm");
write_bytes("$tmp/empty", '');
refuses('empty artifact', qr/empty.*artifact/i, @args, '--artifact', "empty=$tmp/empty");

my $sentinel = "$tmp/not basm; literal path";
write_bytes($sentinel, "#!/bin/sh\nexit 91\n");
chmod 0700, $sentinel or die $!;
($rc, $out, $err) = run($^X, $script, '--basm', $sentinel, @artifacts);
is($rc, 0, 'collector hashes but never invokes supplied executable') or diag($err);
is(decode_json($out)->{tools}->{basm}->{path}, $sentinel, 'spaces and metacharacters remain path data');
chmod 0600, $sentinel or die $!;
refuses('nonexecutable tool', qr/not executable/, '--basm', $sentinel, @artifacts);

my $mirror = "$tmp/repo";
for my $entry (@{$inventory->{source_evidence}}, @{$inventory->{workload}->{fixtures}}) {
    make_path(dirname("$mirror/$entry->{path}"));
    copy("$root/$entry->{path}", "$mirror/$entry->{path}") or die "copy: $!\n";
}
my @mirror_args = ('--repo-root', $mirror, '--basm', $basm, @artifacts);
($rc, $out, $err) = run($^X, $script, @mirror_args);
is($rc, 0, 'relocated source root accepted before mutation') or diag($err);
my $fixture = "$mirror/$inventory->{workload}->{fixtures}->[0]->{path}";
rename $fixture, "$fixture.moved" or die $!;
refuses('fixture path drift', qr/missing.*corpus/i, @mirror_args);
rename "$fixture.moved", $fixture or die $!;
write_bytes($fixture, read_bytes($fixture) . "; corpus drift\n");
refuses('fixture content drift', qr/corpus checksum drift/, @mirror_args);
copy("$root/$inventory->{workload}->{fixtures}->[0]->{path}", $fixture) or die $!;
my $source = "$mirror/toolchain/BearBasm/modules/01_foundation.inc";
my $changed = read_bytes($source);
$changed =~ s/sym_find/sym_moved/g;
write_bytes($source, $changed);
refuses('consumer source anchor drift', qr/source anchor drift/, @mirror_args);

is(sha256_hex(read_bytes($basm)), $basm_sha, 'basm bytes unchanged across serial test run');
diag("basm sha256: $basm_sha");
diag("manifest sha256: " . sha256_hex(read_bytes("$tmp/evidence.json")));
diag("evidence and exact serial assembly argv: $tmp") if $ENV{LAB_KEEP};
done_testing();
PERL
