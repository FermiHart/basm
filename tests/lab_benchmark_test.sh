#!/bin/sh
# INV-593: bounded measurement is separate from identity and never self-promotes.
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
die "unexpected arguments\n" if @ARGV;
my $lab = "$root/toolchain/BearBasm/lab";
my $runner = "$lab/benchmark.pl";
my $tmp = tempdir('ic02-tests-XXXXXX', TMPDIR => 1, CLEANUP => !$ENV{LAB_KEEP});
sub bytes { open my $f, '<:raw', $_[0] or die "$!: $_[0]"; local $/; return <$f> // '' }
sub write_bytes { open my $f, '>:raw', $_[0] or die $!; print {$f} $_[1]; close $f or die $! }
my $seq = 0;
sub run {
    my @argv = @_;
    my $n = ++$seq;
    my $pid = fork(); die $! unless defined $pid;
    if (!$pid) {
        open STDOUT, '>', "$tmp/$n.out" or die $!;
        open STDERR, '>', "$tmp/$n.err" or die $!;
        exec {$argv[0]} @argv; die $!;
    }
    waitpid($pid, 0); return ($? >> 8, bytes("$tmp/$n.out"), bytes("$tmp/$n.err"));
}
my ($rc, $out, $err) = run($^X, $runner, '--help');
is($rc, 0, 'measurement runner help available without tools');
like($out, qr/--baseline.*--output-dir/s, 'explicit execution and retained output CLI');
BAIL_OUT('measurement runner missing') if $rc;
require $runner;
is(BasmMeasurement::median(4, 1, 3, 2), 2.5, 'even median');
is(BasmMeasurement::statistics(1, 2, 3)->{mad}, 1, 'absolute MAD');
my ($stats, $status) = BasmMeasurement::summarize([map { {seconds => {baseline => $_, candidate => 1}} } (1, 2, 4, 8, 16)], [qw(baseline candidate)]);
is($status, 'INCONCLUSIVE', 'deterministic high dispersion never green');
($stats, $status) = BasmMeasurement::summarize([map { {seconds => {baseline => $_->[0], candidate => $_->[1]}} }
    ([1, 100], [10, 1], [100, 10])], [qw(baseline candidate)]);
is($stats->{paired_ratio}->{median}, 10, 'median of paired ratios, not ratio of medians');
eval { BasmMeasurement::statistics(1, 0, 2) }; like($@, qr/nonpositive/, 'zero clock sample rejected');

my $sentinel = "$tmp/not basm; literal executable";
write_bytes($sentinel, "#!$^X\nopen my \$f, '>', '$tmp/EXECUTED' or die \$!; print {\$f} 'bad'; exit 91;\n");
chmod 0700, $sentinel or die $!;
my @args = ('--baseline', $sentinel, '--output-dir', "$tmp/refused");
sub refuses {
    my ($name, $pattern, @opts) = @_;
    my ($status, $stdout, $stderr) = run($^X, $runner, @opts);
    ok($status != 0, "$name: refused");
    like($stderr, $pattern, "$name: diagnostic");
}
refuses('rounds upper bound', qr/rounds/, @args, '--rounds', 16);
refuses('rounds lower bound', qr/rounds/, @args, '--rounds', 0);
refuses('warmup bound', qr/warmups/, @args, '--warmups', 4);
refuses('total budget upper bound', qr/total-seconds/, @args, '--total-seconds', 61);
refuses('command budget upper bound', qr/command-seconds/, @args, '--command-seconds', 11);
refuses('no arbitrary shell flags', qr/Unknown option|usage/, @args, '--baseline-args', '; touch bad');
refuses('invalid profile', qr/profile/, @args, '--baseline-profile', 'public; exit');
refuses('missing tool', qr/missing|executable/, @args, '--baseline', "$tmp/absent");
refuses('missing inspector', qr/missing|executable/, @args, '--readelf', "$tmp/absent");
refuses('existing output directory', qr/output.*exist/, @args, '--output-dir', $tmp);
my $inventory = decode_json(bytes("$lab/inventory-v1.json"));
my $mirror = "$tmp/repo";
for my $entry (@{$inventory->{source_evidence}}, @{$inventory->{workload}->{fixtures}}) {
    make_path(dirname("$mirror/$entry->{path}"));
    copy("$root/$entry->{path}", "$mirror/$entry->{path}") or die $!;
}
my $fixture = "$mirror/$inventory->{workload}->{fixtures}->[0]->{path}";
write_bytes($fixture, bytes($fixture) . "; drift\n");
refuses('pinned corpus drift before execution', qr/corpus checksum drift/, @args, '--repo-root', $mirror);
ok(!-e "$tmp/EXECUTED", 'all preflight negatives leave executable uninvoked');
refuses('child nonzero', qr/command failed/, @args);
ok(-e "$tmp/EXECUTED", 'literal metacharacter path invoked as argv, not shell');
is(decode_json(bytes("$tmp/refused/result.json"))->{status}, 'REFUSED', 'failure receipt retained, no measured success');

my $empty = "$tmp/empty-output";
write_bytes($empty, "#!$^X\nexit 0;\n"); chmod 0700, $empty;
refuses('success without output', qr/missing.*output/, '--baseline', $empty, '--output-dir', "$tmp/no-output");
my $hang = "$tmp/hang";
write_bytes($hang, "#!$^X\nsleep 30;\n"); chmod 0700, $hang;
refuses('bounded child timeout', qr/timeout/, '--baseline', $hang, '--output-dir', "$tmp/timeout", '--command-seconds', '0.05');
refuses('bounded total timeout', qr/timeout/, '--baseline', $hang, '--output-dir', "$tmp/total-timeout", '--total-seconds', '0.05');

my $receipt = decode_json(bytes("$tmp/refused/result.json"));
ok(exists $receipt->{executable_snapshots}->{baseline}, 'executable snapshot recorded even when invocation refuses');
BAIL_OUT('executable snapshots missing') unless exists $receipt->{executable_snapshots}->{baseline};
my $saved = $receipt->{executable_snapshots}->{baseline};
is($saved->{purpose}, 'EVIDENCE_ONLY_NOT_EXECUTED', 'snapshot is not substituted into measured argv');
is_deeply($saved->{original}, $receipt->{inputs_before}->{baseline}, 'original requested/resolved paths and SHA retained');
is(bytes($saved->{snapshot_before}->{path}), bytes($sentinel), 'snapshot contains actual original executable bytes');
is($saved->{snapshot_before}->{sha256}, $saved->{original}->{sha256}, 'snapshot SHA equals frozen original');
my ($assembly) = grep { $_->{purpose} eq 'validation-assembly' } @{$receipt->{commands}};
is($assembly->{argv}->[0], $sentinel, 'runner still invokes original literal path');
ok(!exists $saved->{snapshot_after}, 'refused run does not claim completed snapshot verification');
refuses('paired stubs refuse before real measurement', qr/command failed/, '--baseline', $sentinel,
    '--candidate', $empty, '--output-dir', "$tmp/paired-stubs");
my $paired = decode_json(bytes("$tmp/paired-stubs/result.json"));
for my $role (qw(baseline candidate)) {
    my $copy = $paired->{executable_snapshots}->{$role};
    is_deeply($copy->{original}, $paired->{inputs_before}->{$role}, "$role stub: both original paths retained");
    is(bytes($copy->{snapshot_before}->{path}), bytes($copy->{original}->{path}), "$role stub: actual executable snapshot bytes");
    is($copy->{snapshot_before}->{sha256}, $copy->{original}->{sha256}, "$role stub: frozen hash verified before invocation");
}

# Private, nonexecuting byte fixtures exercise both copy and end-of-run verification.
my $source = "$tmp/snapshot source; not executed";
write_bytes($source, "\x7fELF\0" . ("frozen bytes\xff" x 7000));
chmod 0700, $source or die $!;
my $frozen = BasmMeasurement::identity($source, 1);
my $clone = "$tmp/executable snapshot; literal";
my $deadline = sub { Time::HiRes::clock_gettime(Time::HiRes::CLOCK_MONOTONIC()) + 10 };
my $snapshot = BasmMeasurement::executable_snapshot($frozen, $clone, $deadline->(), 1);
is(bytes($clone), bytes($source), 'multi-chunk binary snapshot is byte exact');
is($snapshot->{sha256}, $frozen->{sha256}, 'actual clone hash verified against frozen original');
is((stat($clone))[2] & 0777, 0500, 'snapshot is owner read/execute only');
isnt((stat($clone))[1], (stat($source))[1], 'snapshot is a copy, not a hard link');
is_deeply(BasmMeasurement::executable_snapshot($frozen, $clone, $deadline->(), 0), $snapshot, 'unchanged retained copy revalidates');
my $original_bytes = bytes($source);
write_bytes($source, 'rebuilt tool');
is(bytes($clone), $original_bytes, 'private original rebuild cannot change retained executable');
eval { BasmMeasurement::executable_snapshot($frozen, $source, $deadline->(), 0) };
like($@, qr/snapshot checksum drift/, 'rebuilt original bytes do not match historical identity');
my $bad_copy = "$tmp/drifted-copy";
eval { BasmMeasurement::executable_snapshot($frozen, $bad_copy, $deadline->(), 1) };
like($@, qr/snapshot checksum drift/, 'source changed since freeze cannot produce an accepted snapshot');
eval { BasmMeasurement::executable_snapshot($frozen, $clone, $deadline->(), 1) };
like($@, qr/create snapshot/, 'existing snapshot never overwritten');
is(bytes($clone), $original_bytes, 'failed overwrite leaves old snapshot intact');
chmod 0700, $clone or die $!;
my $mutated = $original_bytes;
substr($mutated, 0, 1) = 'X';
write_bytes($clone, $mutated);
eval { BasmMeasurement::executable_snapshot($frozen, $clone, $deadline->(), 0) };
like($@, qr/snapshot checksum drift/, 'same-size snapshot mutation rejected on recheck');
write_bytes($source, $original_bytes . 'growing source');
eval { BasmMeasurement::executable_snapshot($frozen, "$tmp/growing-copy", $deadline->(), 1) };
like($@, qr/snapshot checksum drift: source grew/, 'copy cannot grow beyond frozen byte count');
write_bytes($source, $original_bytes);
my $alias = "$tmp/snapshot-alias";
symlink $source, $alias or die $!;
eval { BasmMeasurement::executable_snapshot($frozen, $alias, $deadline->(), 0) };
like($@, qr/snapshot.*regular|snapshot.*symlink/, 'symlink is not a retained copy even with matching SHA');
eval { BasmMeasurement::executable_snapshot($frozen, "$tmp/too-late", 0, 1) };
like($@, qr/snapshot.*timeout/, 'snapshot creation consumes the existing total budget');
ok(!-e "$tmp/too-late", 'expired budget does not start copying');
eval { BasmMeasurement::executable_snapshot($frozen, $clone, 0, 0) };
like($@, qr/snapshot.*timeout/, 'snapshot recheck also consumes the existing total budget');
if ($ENV{LAB_STUB_ONLY}) {
    diag('stub-only: no current basm, real assembly smoke or linkage inspection invoked');
    diag("retained tests: $tmp") if $ENV{LAB_KEEP};
    done_testing();
    exit 0;
}

my $basm = abs_path($ENV{BASM} // "$root/toolchain/BearBasm/basm");
BAIL_OUT('existing trusted basm required; never build here') unless $basm && -x $basm;
my $before = sha256_hex(bytes($basm));
my $noop = "$tmp/stale-output";
write_bytes($noop, "#!$^X\n" . 'use strict; use warnings; my $state = __FILE__ . ".state"; exit 0 if -e $state; open my $f, ">", $state or die $!; close $f; exec {' . "'$basm'} '$basm', \@ARGV;\n");
chmod 0700, $noop;
refuses('no stale output on warmup', qr/missing assembly output/, '--baseline', $noop, '--output-dir', "$tmp/stale");
my $wrong = "$tmp/wrong-object";
write_bytes($wrong, "#!$^X\n" . 'use strict; use warnings; my @a = @ARGV; system {' . "'$basm'} '$basm', \@a; exit 1 if \$?; " .
    'my ($i) = grep { $a[$_] eq "-o" } 0..$#a; open my $f, ">>", $a[$i+1] or die $!; print {$f} "changed"; close $f;' . "\n");
chmod 0700, $wrong;
refuses('candidate mismatch', qr/candidate object mismatch/, '--baseline', $basm, '--candidate', $wrong, '--output-dir', "$tmp/mismatch");

my $tamper = "$tmp/tamper-proof";
write_bytes($tamper, "#!$^X\n" . 'use strict; use warnings; my $p = $ARGV[-1] . ".basmproof"; if (-f $p) { open my $f, "<", $p or die $!; local $/; my $s = <$f>; close $f; $s =~ s/output_sha256: [a-f0-9]+/output_sha256: wrong/; open $f, ">", $p or die $!; print {$f} $s; close $f; } exec {"/usr/bin/readelf"} "/usr/bin/readelf", @ARGV;' . "\n");
chmod 0700, $tamper;
refuses('proof tamper outside clock', qr/proof identity mismatch: output_sha256/, '--baseline', $basm,
    '--readelf', $tamper, '--rounds', 5, '--warmups', 1, '--output-dir', "$tmp/proof-tamper");

copy("$root/$inventory->{workload}->{fixtures}->[0]->{path}", $fixture) or die $!;
my $drift = "$tmp/drift-inspector";
my $drift_source = "$mirror/surfaces/blibc/core/mem/memcmp.c";
write_bytes($drift, "#!$^X\nopen my \$f, '>>', '$drift_source' or die \$!; print {\$f} qq(\n); close \$f; " .
    'exec {"/usr/bin/readelf"} "/usr/bin/readelf", @ARGV;' . "\n");
chmod 0700, $drift;
refuses('before/after source identity drift', qr/identity drift before\/after/, '--baseline', $basm, '--repo-root', $mirror,
    '--readelf', $drift, '--rounds', 5, '--warmups', 1, '--output-dir', "$tmp/source-drift");
my @review = $ENV{LAB_REVIEW} ? ('--review-linkage', '--baseline-object', "$root/toolchain/BearBasm/build/bear/basm.o",
    '--candidate-object', "$root/toolchain/BearBasm/build/bear/basm.o") : ();
($rc, $out, $err) = run($^X, $runner, '--baseline', $basm, '--candidate', $basm, @review,
    '--candidate-profile', 'public', '--output-dir', "$tmp/current", '--rounds', 5, '--warmups', 1);
ok($rc == 0 || $rc == 2, 'real same-binary smoke completes, stability is not a test threshold') or diag($err);
BAIL_OUT('real harness failed') if $rc != 0 && $rc != 2;
my $r = decode_json(bytes("$tmp/current/result.json"));
is($r->{schema}, 'BASM-IC02-MEASUREMENT-v1', 'separate measured schema');
is($r->{evidence_kind}, 'MEASURED', 'actual measurements, not collector mutation');
is($r->{identity_status}, 'UNCHANGED', 'before/after identities match');
for my $role (qw(baseline candidate)) {
    my $copy = $r->{executable_snapshots}->{$role};
    is(bytes($copy->{snapshot_before}->{path}), bytes($basm), "$role: actual executable bytes retained");
    is_deeply($copy->{original}, $r->{inputs_before}->{$role}, "$role: original identity retained");
    is_deeply($copy->{snapshot_after}, $copy->{snapshot_before}, "$role: copy identity verified after measurement");
    is($copy->{status}, 'UNCHANGED', "$role: verified copy status");
}
is($r->{protocol}->{rounds}, 5, 'fixed rounds retained');
is($r->{protocol}->{warmups}, 1, 'warmups retained separately');
is($r->{protocol}->{attempts}, 1, 'one attempt, no loop until green');
is($r->{budgets}->{authority}, 'OPERATIONAL_BATCH', 'budgets not an independent signature');
is(scalar @{$r->{cases}}, 6, 'bare and unsigned cases for each real fixture');
for my $case (@{$r->{cases}}) {
    is(scalar @{$case->{pairs}}, 5, "$case->{id}: five pairs");
    is(scalar @{$case->{warmups}}, 1, "$case->{id}: one warmup pair");
    is_deeply($case->{pairs}->[0]->{order}, ['baseline', 'candidate'], 'first order AB');
    is_deeply($case->{pairs}->[1]->{order}, ['candidate', 'baseline'], 'second order BA');
    for my $pair (@{$case->{pairs}}) {
        ok($pair->{seconds}->{baseline} > 0 && $pair->{seconds}->{candidate} > 0, 'real monotonic positive samples');
    }
    ok($case->{statistics}->{paired_ratio}->{median} > 0, 'paired ratio reported');
    like($case->{status}, qr/\A(?:STABLE|INCONCLUSIVE)\z/, 'no automatic speedup promotion');
    is($case->{validation}->{object_equality}, 'BYTE_IDENTICAL', 'same STT_FILE source, object parity');
}
ok($r->{hardware}->{uname} && $r->{hardware}->{cpuinfo}, 'CPU and OS recorded');
if ($ENV{LAB_REVIEW}) {
    is(scalar @{$r->{linkage}}, 8, 'three reviewed pilots, both basm lanes and host Bear include path');
    my ($map) = grep { $_->{role} eq 'baseline' && $_->{pilot} =~ /memcmp/ } @{$r->{linkage}};
    my ($site) = grep { $_->{path} eq $basm && $_->{symbol} eq 'sym_find' } @{$map->{sites}};
    is($site->{object_to_final_window}->{status}, 'RELOCATION_MASKED_TEXT_MATCH', 'stripped local name maps by checked text, not name guessing');
    like(join('\n', @{$site->{call_lines}}), qr/call.*<bear_memcmp>/, 'mapped final window actually calls named provider');
    is($map->{dynamic_call_distribution}, 'NOT_MEASURED', 'static evidence is not dynamic coverage');
    my %inspection;
    my $object = "$root/toolchain/BearBasm/build/bear/basm.o";
    for my $path ($object, $basm) {
        for my $cmd (['nm', '/usr/bin/nm', '-a', $path], ['headers', '/usr/bin/readelf', '-SW', $path],
                     ['relocations', '/usr/bin/readelf', '-rW', $path]) {
            my ($key, @argv) = @$cmd;
            my ($exit, $text) = run(@argv); die "inspection failed\n" if $exit;
            $inspection{$path}->{$key} = $text;
        }
    }
    my $fake_final = "$tmp/changed-final";
    my $changed = bytes($basm);
    # The first byte of the mapped function is not a relocation.
    my ($text_offset) = $inspection{$basm}->{headers} =~ /\.text\s+PROGBITS\s+[a-f0-9]+\s+([a-f0-9]+)/;
    my ($text_addr) = $inspection{$basm}->{headers} =~ /\.text\s+PROGBITS\s+([a-f0-9]+)/;
    my $offset = hex($text_offset) + $site->{object_to_final_window}->{final_address} - hex($text_addr);
    substr($changed, $offset, 1) = chr(ord(substr($changed, $offset, 1)) ^ 1);
    write_bytes($fake_final, $changed);
    $inspection{$fake_final} = $inspection{$basm};
    eval { BasmMeasurement::static_window($object, $fake_final, 'sym_find', 'main', \%inspection) };
    like($@, qr/static object\/final mismatch/, 'same symbols with changed final bytes cannot claim mapping');
}
is(sha256_hex(bytes($basm)), $before, 'shared basm not rebuilt or modified');
diag("retained tests: $tmp") if $ENV{LAB_KEEP};
done_testing();
PERL
