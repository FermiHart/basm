#!/usr/bin/env perl
package BasmMeasurement;
use strict;
use warnings;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(O_WRONLY O_CREAT O_EXCL);
use File::Basename qw(dirname);
use File::Spec;
use Getopt::Long qw(GetOptions Configure);
use JSON::PP;
use POSIX qw(strftime uname);
use Time::HiRes qw(clock_gettime clock_getres CLOCK_MONOTONIC alarm);

# INV-593: fixed, paired observations; neither stability nor hashes prove impact.
sub median {
    my @v = sort { $a <=> $b } @_;
    die "empty samples\n" unless @v;
    return @v % 2 ? $v[int(@v / 2)] : ($v[@v / 2 - 1] + $v[@v / 2]) / 2;
}
sub statistics {
    my @v = @_;
    die "nonpositive sample\n" if grep { !defined($_) || $_ <= 0 } @v;
    my $m = median(@v);
    my $mad = median(map { abs($_ - $m) } @v);
    return {median => $m, mad => $mad, relative_mad => $mad / $m, count => 0 + @v};
}
sub summarize {
    my ($pairs, $roles) = @_;
    my %s = map { my $role = $_; $role => statistics(map { $_->{seconds}->{$role} } @$pairs) } @$roles;
    if (@$roles == 2) {
        $s{paired_ratio} = statistics(map { $_->{seconds}->{baseline} / $_->{seconds}->{candidate} } @$pairs);
    }
    my $stable = !grep { $_->{relative_mad} > 0.25 } values %s;
    return (\%s, $stable ? 'STABLE' : 'INCONCLUSIVE');
}
sub bytes {
    my ($path) = @_;
    open my $f, '<:raw', $path or die "read $path: $!\n";
    my $s = '';
    while (1) {
        my $n = read($f, my $buf, 65536);
        die "read $path: $!\n" unless defined $n;
        last unless $n;
        $s .= $buf;
        die "inspection/output exceeds 16 MiB: $path\n" if length($s) > 16 * 1024 * 1024;
    }
    return $s;
}
sub write_bytes {
    open my $f, '>:raw', $_[0] or die "write $_[0]: $!\n";
    print {$f} $_[1] or die "write: $!\n";
    close $f or die "close: $!\n";
}
sub identity {
    my ($path, $executable) = @_;
    die "invalid path\n" unless defined($path) && length($path) && $path !~ /[\x00-\x1f\x7f]/;
    $path = File::Spec->rel2abs($path);
    die "missing or empty file: $path\n" unless -f $path && -r $path && -s $path;
    die "not executable: $path\n" if $executable && !-x $path;
    open my $f, '<:raw', $path or die $!;
    my @a = stat($f);
    my $sha = Digest::SHA->new(256)->addfile($f)->hexdigest;
    my @b = stat($f);
    close $f;
    my @c = stat($path);
    for (0, 1, 7, 9, 10) {
        die "identity changed while hashing: $path\n" unless defined($c[$_]) && $a[$_] == $b[$_] && $a[$_] == $c[$_];
    }
    return {path => $path, resolved_path => abs_path($path), bytes => 0 + $a[7], sha256 => $sha};
}

# INV-593: retain independent executable bytes, not just rebuildable tool paths.
sub executable_snapshot {
    my ($original, $path, $deadline, $create) = @_;
    my $remaining = $deadline - clock_gettime(CLOCK_MONOTONIC);
    die "executable snapshot timeout\n" if $remaining <= 0;
    my $id;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "executable snapshot timeout\n" };
        alarm($remaining);
        if ($create) {
            open my $source, '<:raw', $original->{path} or die "open snapshot source: $!\n";
            sysopen my $copy, $path, O_WRONLY | O_CREAT | O_EXCL, 0600 or die "create snapshot $path: $!\n";
            binmode $copy or die "snapshot binmode: $!\n";
            my $copied = 0;
            while (1) {
                my $n = read($source, my $buffer, 65536);
                die "read snapshot source: $!\n" unless defined $n;
                last unless $n;
                $copied += $n;
                die "snapshot checksum drift: source grew\n" if $copied > $original->{bytes};
                print {$copy} $buffer or die "write snapshot: $!\n";
            }
            close $source or die "close snapshot source: $!\n";
            close $copy or die "close snapshot: $!\n";
            chmod 0500, $path or die "chmod snapshot: $!\n";
        }
        die "snapshot must be a regular file, not a symlink: $path\n" if -l $path || !-f $path;
        $id = identity($path, 1);
        die "snapshot checksum drift: $path\n"
            unless $id->{bytes} == $original->{bytes} && $id->{sha256} eq $original->{sha256};
        die "executable snapshot timeout\n" if clock_gettime(CLOCK_MONOTONIC) > $deadline;
        1;
    };
    my $error = $@;
    alarm(0);
    die $error unless $ok;
    return $id;
}

sub static_window {
    my ($object, $final, $symbol, $anchor, $inspection) = @_;
    my (%syms, %section);
    for my $path ($object, $final) {
        $syms{$path} = {};
        for my $line (split /\n/, $inspection->{$path}->{nm}) {
            $syms{$path}->{$2} = hex($1) if $line =~ /^([0-9a-fA-F]+)\s+[tT]\s+(\S+)$/;
        }
        my @text = $inspection->{$path}->{headers} =~ /^\s*\[\s*\d+\]\s+\.text\s+PROGBITS\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)/m;
        die "missing ELF text section: $path\n" unless @text == 3;
        $section{$path} = [map { hex($_) } @text];
    }
    return undef if exists $syms{$final}->{$symbol} || !exists $syms{$object}->{$symbol};
    die "missing mapping anchor $anchor\n" unless exists $syms{$object}->{$anchor} && exists $syms{$final}->{$anchor};
    my $base = $syms{$final}->{$anchor} - $syms{$object}->{$anchor};
    my $lo = $syms{$object}->{$symbol};
    my ($hi) = sort { $a <=> $b } grep { $_ > $lo } (values %{$syms{$object}}, $section{$object}->[2]);
    die "invalid static symbol range\n" unless defined $hi && $hi > $lo && $hi - $lo <= 131072;
    my $length = $hi - $lo;
    my $final_offset = $lo + $base - $section{$final}->[0];
    die "mapped range outside final text\n" unless $final_offset >= 0 && $final_offset + $length <= $section{$final}->[2];
    my $a = substr(bytes($object), $section{$object}->[1] + $lo, $length);
    my $b = substr(bytes($final), $section{$final}->[1] + $final_offset, $length);
    my $relocs = $inspection->{$object}->{relocations};
    my ($text_relocs) = $relocs =~ /Relocation section '\.rela.text'[^\n]*\n(.*?)(?=\nRelocation section|\z)/s;
    my $masked = 0;
    for my $line (split /\n/, $text_relocs // '') {
        next unless $line =~ /^([0-9a-fA-F]+)\s+\S+\s+(R_X86_64_\S+)/;
        my ($offset, $type) = (hex($1), $2);
        next if $offset < $lo || $offset >= $hi;
        my $n = $type eq 'R_X86_64_64' ? 8 : $type =~ /^R_X86_64_(?:PC32|PLT32|32S?)$/ ? 4 : 0;
        die "unsupported text relocation $type\n" unless $n && $offset + $n <= $hi;
        substr($a, $offset - $lo, $n) = "\0" x $n;
        substr($b, $offset - $lo, $n) = "\0" x $n;
        $masked += $n;
    }
    die "static object/final mismatch: $symbol\n" unless $a eq $b && $length > $masked;
    return {status => 'RELOCATION_MASKED_TEXT_MATCH', anchor => $anchor, anchor_delta => $base,
        object_offset => $lo, final_address => $lo + $base, length => $length,
        masked_relocation_bytes => $masked, masked_sha256 => sha256_hex($a),
        limitation => 'Corroborates this text window, not relocation values, build provenance or dynamic execution'};
}

sub main {
    Configure(qw(no_auto_abbrev no_ignore_case));
    my ($root, $baseline, $candidate, $dir, $help, $review, $baseline_obj, $candidate_obj, $blane, $clane);
    my ($bp, $cp, $rounds, $warmups, $seconds, $total) = ('compat', 'compat', 15, 3, 10, 60);
    my ($readelf, $nm, $objdump) = ('/usr/bin/readelf', '/usr/bin/nm', '/usr/bin/objdump');
    GetOptions('repo-root=s' => \$root, 'baseline=s' => \$baseline, 'candidate=s' => \$candidate,
        'output-dir=s' => \$dir, 'baseline-profile=s' => \$bp, 'candidate-profile=s' => \$cp,
        'baseline-lane=s' => \$blane, 'candidate-lane=s' => \$clane,
        'rounds=i' => \$rounds, 'warmups=i' => \$warmups, 'command-seconds=f' => \$seconds,
        'total-seconds=f' => \$total, 'readelf=s' => \$readelf, 'nm=s' => \$nm, 'objdump=s' => \$objdump,
        'review-linkage' => \$review, 'baseline-object=s' => \$baseline_obj,
        'candidate-object=s' => \$candidate_obj, 'help' => \$help) or die "usage: perl lab/benchmark.pl --help\n";
    die "unexpected arguments\n" if @ARGV;
    if ($help) {
        print <<'HELP';
Usage: perl lab/benchmark.pl --baseline PATH --output-dir NEW_DIRECTORY [options]
  --candidate PATH          Optional trusted assembler, not assembled code
  --baseline-profile NAME   compat (no selector), beyond, or public
  --candidate-profile NAME  Same choices; explicit differences recorded
  --baseline-lane LABEL --candidate-lane LABEL  Caller declarations, not provenance
  --rounds N                5..15 paired rounds, default 15
  --warmups N               1..3 warmup pairs, default 3
  --command-seconds N       >0..10 per command, default 10
  --total-seconds N         >0..60 whole execution budget, default 60
  --repo-root PATH          Default: repository containing this script
  --readelf PATH --nm PATH --objdump PATH  Explicit host inspectors
  --review-linkage          Inspect three inventory pilots using existing objects
  --baseline-object PATH    Required with --review-linkage; no rebuild or inference
  --candidate-object PATH   Required if reviewing a candidate

Perl stdlib, Linux x86-64 host. Fixed inventory-v1 corpus, bare assembly and
unsigned attestation separately. Direct argv exec, clean child environment,
no shell commands, signing, cache, builds, gate, or generated-code execution.
Only run trusted tools: process-group deadlines are NOT a hostile-code sandbox.
All outputs and readable result.json are retained in a NEW private directory.
Executable snapshots are SHA-verified evidence only; commands use original paths.
Exit 0: STABLE, 2: INCONCLUSIVE, 1: REFUSED/error. Never retry until green.
HELP
        return 0;
    }
    die "rounds must be 5..15\n" unless $rounds >= 5 && $rounds <= 15;
    die "warmups must be 1..3\n" unless $warmups >= 1 && $warmups <= 3;
    die "command-seconds must be >0..10\n" unless $seconds > 0 && $seconds <= 10;
    die "total-seconds must be >0..60\n" unless $total > 0 && $total <= 60;
    die "invalid profile\n" if grep { !/\A(?:compat|public|beyond)\z/ } ($bp, $cp);
    die "--baseline and --output-dir required\n" unless defined $baseline && defined $dir;
    die "Linux x86-64 host required\n" unless $^O eq 'linux' && (uname())[4] eq 'x86_64';
    my $lab = dirname(abs_path(__FILE__));
    $root = abs_path($root // "$lab/../../..");
    die "missing repo root\n" unless defined $root && -d $root;
    $dir = File::Spec->rel2abs($dir);
    die "output directory exists or invalid parent\n" if -e $dir || -l $dir || !-d dirname($dir);
    my $json = JSON::PP->new->canonical->pretty;
    my %inputs = (runner => identity(__FILE__), inventory => identity("$lab/inventory-v1.json"),
        collector => identity("$lab/evidence.pl"), perl => identity($^X, 1),
        baseline => identity($baseline, 1), readelf => identity($readelf, 1),
        nm => identity($nm, 1), objdump => identity($objdump, 1));
    $inputs{candidate} = identity($candidate, 1) if defined $candidate;
    my @roles = defined($candidate) ? qw(baseline candidate) : qw(baseline);
    my %profile = (baseline => $bp, candidate => $cp);
    my $inventory = decode_json(bytes($inputs{inventory}->{path}));
    die "unsupported inventory\n" unless $inventory->{schema} eq 'BASM-IC02-INVENTORY-v1';
    for my $entry (@{$inventory->{source_evidence}}, @{$inventory->{workload}->{fixtures}}) {
        my $path = "$root/$entry->{path}";
        my $id = identity($path);
        die "corpus checksum drift: $path\n" if $entry->{sha256} && $entry->{sha256} ne $id->{sha256};
        my $text = bytes($path);
        for my $anchor (@{$entry->{anchors} // []}) {
            die "source anchor drift: $path\n" if index($text, $anchor) < 0;
        }
        $inputs{$entry->{path}} = $id;
    }
    if ($review) {
        die "--baseline-object required for linkage\n" unless defined $baseline_obj;
        die "--candidate-object required for linkage\n" if defined($candidate) && !defined($candidate_obj);
        $inputs{baseline_object} = identity($baseline_obj);
        $inputs{candidate_object} = identity($candidate_obj) if defined $candidate;
        for my $path (qw(toolchain/stage3/bear toolchain/stage3/bear.o toolchain/stage3/bear_pp.o
                         toolchain/BearBasm/build/bear/sign.o surfaces/blibc/build/libblibc.a)) {
            $inputs{$path} = identity("$root/$path");
        }
    }
    mkdir $dir, 0700 or die "mkdir $dir: $!\n";
    my $start = clock_gettime(CLOCK_MONOTONIC);
    my $deadline = $start + $total;
    my $seq = 0;
    my $report = {
        schema => 'BASM-IC02-MEASUREMENT-v1', evidence_kind => 'MEASURED', status => 'REFUSED',
        created_utc => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime), repo_root => $root, output_dir => $dir,
        protocol => {rounds => $rounds, warmups => $warmups, attempts => 1,
            clock => 'CLOCK_MONOTONIC', clock_resolution_seconds => clock_getres(CLOCK_MONOTONIC),
            paired_ratio => 'baseline_seconds / candidate_seconds; >1 means candidate faster',
            relative_mad_max => 0.25, order => 'AB, BA alternating; each pair adjacent',
            cache => 'warm OS page cache after validation and warmups; new process each invocation; no basm cache',
            cold_cache => 'NOT_MEASURED; no cache eviction or root operations',
            measurement => 'fork+exec+wait wall latency, includes process startup and output writes; not function latency',
            validation => 'ELF inspection before timing; every emitted object/proof checked after stop clock',
            child_environment => {LC_ALL => 'C', LANG => 'C', TZ => 'UTC', SOURCE_DATE_EPOCH => '0',
                                  PATH => '/usr/bin:/bin', HOME => $dir, TMPDIR => $dir}},
        budgets => {authority => 'OPERATIONAL_BATCH', independent_council_signature => 'NONE',
            basis => 'IC01-IC05 batch and standing user authorization; not independent council ratification',
            analysis => {rss_mib_max => 256, wall_seconds_max => 10, enforcement => 'FUTURE_ANALYSIS_NOT_RUN'},
            search => {candidates_max => 32, total_seconds_max => 60, passes_max => 1, status => 'NOT_RUN'},
            runner => {command_seconds_max => $seconds, total_seconds_max => $total, attempts_max => 1},
            impact_target_percent => 5, inherited_text_bytes_max => 750000, inherited_bss_bytes_max => 8000000},
        inputs_before => \%inputs, profiles => \%profile,
        lanes => {status => 'CALLER_DECLARED_NOT_AUTHENTICATED', baseline => $blane, candidate => $clane,
                  build_flags => 'No compiler invocation receipt; inspect hashed source build rules separately'},
        workload => {%{$inventory->{workload}}, sha256 => sha256_hex($json->encode($inventory->{workload}))},
        commands => [], cases => [], linkage => [], executable_snapshots => {},
        gaps => ['No complete Bear C/prelude/include NUL-scan distribution or timing.',
            'No name-length/collision/call-count distribution, function-kernel latency, signing or energy measurement.',
            'No analysis engine, optimization search, RSS or full package-size accounting measured.',
            'Executable snapshots are evidence only, not retained interpreters/libraries/build closure or a replay guarantee.',
            'Static symbols/calls are not dynamic coverage, IFUNC resolution, or authenticated source-to-build provenance.',
            'No global gate or shared build; integrated batch acceptance remains with main.']};
    my $run = sub {
        my ($purpose, @argv) = @_;
        my $remaining = $deadline - clock_gettime(CLOCK_MONOTONIC);
        die "total budget timeout\n" if $remaining <= 0;
        my $limit = $remaining < $seconds ? $remaining : $seconds;
        my $n = ++$seq;
        my ($stdout, $stderr) = ("$dir/cmd-$n.out", "$dir/cmd-$n.err");
        open my $o, '>:raw', $stdout or die $!;
        open my $e, '>:raw', $stderr or die $!;
        my $record = {id => $n, purpose => $purpose, argv => \@argv, stdout => $stdout, stderr => $stderr};
        push @{$report->{commands}}, $record;
        my $pid;
        my $t = clock_gettime(CLOCK_MONOTONIC);
        my ($status, $elapsed);
        my $ok = eval {
            local $SIG{ALRM} = sub { die "command timeout ($purpose)\n" };
            $pid = fork(); die "fork: $!\n" unless defined $pid;
            if (!$pid) {
                POSIX::setpgid(0, 0) == 0 or POSIX::_exit(127);
                open STDOUT, '>&', $o or POSIX::_exit(127);
                open STDERR, '>&', $e or POSIX::_exit(127);
                open STDIN, '<', '/dev/null' or POSIX::_exit(127);
                chdir $dir or POSIX::_exit(127);
                %ENV = %{$report->{protocol}->{child_environment}};
                exec {$argv[0]} @argv or POSIX::_exit(127);
            }
            POSIX::setpgid($pid, $pid);
            alarm($limit);
            waitpid($pid, 0) == $pid or die "waitpid: $!\n";
            $status = $?;
            $elapsed = clock_gettime(CLOCK_MONOTONIC) - $t;
            alarm(0);
            1;
        };
        my $error = $@;
        alarm(0);
        if ($pid && $pid > 0) {
            kill 'KILL', -$pid; # Also reap/terminate ordinary descendants on refusal.
            if (!$ok) { kill 'KILL', $pid; waitpid($pid, 0); }
        }
        close $o; close $e;
        $record->{wait_status} = $status;
        $record->{error} = $error if !$ok;
        $record->{seconds} = $elapsed if $purpose =~ /\A(?:sample|warmup):/ && defined $elapsed;
        die $error unless $ok;
        die "command failed ($purpose), status $status; $stderr\n" if $status;
        die "total budget timeout\n" if clock_gettime(CLOCK_MONOTONIC) > $deadline;
        return ($elapsed, bytes($stdout), $n);
    };
    my $ok = eval {
        for my $role (@roles) {
            my $snapshot = $report->{executable_snapshots}->{$role} = {
                original => $inputs{$role}, purpose => 'EVIDENCE_ONLY_NOT_EXECUTED'};
            $snapshot->{snapshot_before} = executable_snapshot($inputs{$role}, "$dir/$role.executable", $deadline, 1);
            $snapshot->{status} = 'COPIED_SHA256_VERIFIED';
        }
        $report->{hardware} = {uname => [uname()], perl_version => "$^V",
            cpuinfo => bytes('/proc/cpuinfo'), os_release => bytes('/etc/os-release'),
            affinity => [bytes('/proc/self/status') =~ /^(Cpus_allowed_list:.*|Mems_allowed_list:.*)$/mg],
            loadavg_before => bytes('/proc/loadavg'), virtualization => 'OS-reported flags only; no bare-metal attestation',
            frequency_policy => {}, os_isa_state => 'XCR0 not probed; no generated ISA executed'};
        for my $path (qw(/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
                         /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver
                         /sys/devices/system/cpu/intel_pstate/no_turbo /sys/fs/cgroup/cpu.max)) {
            $report->{hardware}->{frequency_policy}->{$path} = -r $path ? bytes($path) : 'UNAVAILABLE';
        }
        my (undef, $evidence) = $run->('identity-collector', $inputs{perl}->{path}, "$lab/evidence.pl",
            '--repo-root', $root, '--basm', $inputs{baseline}->{path}, '--artifact', "baseline-file=$inputs{baseline}->{path}");
        write_bytes("$dir/identity-only.json", $evidence);

        for my $mode (qw(bare unsigned-attestation)) {
            for my $fixture (@{$inventory->{workload}->{fixtures}}) {
                my $id = "$mode-$fixture->{id}";
                my $case = {id => $id, mode => $mode, fixture => $fixture->{id}, partition => $fixture->{partition},
                    warmups => [], pairs => [], validation => {object_equality => 'PENDING'}, outputs => {}};
                push @{$report->{cases}}, $case;
                my (%argv, %objects, %proofs, %expected_object, %expected_proof);
                my $source = "$root/$fixture->{path}";
                for my $role (@roles) {
                    $objects{$role} = "$dir/$id-$role.o";
                    $proofs{$role} = "$objects{$role}.basmproof";
                    my @cmd = ($inputs{$role}->{path});
                    push @cmd, '--target-profile', $profile{$role} if $profile{$role} ne 'compat';
                    push @cmd, '-f', 'elf64', '-o', $objects{$role};
                    push @cmd, '--emit-attestation', $proofs{$role} if $mode ne 'bare';
                    push @cmd, $source;
                    $argv{$role} = \@cmd;
                }
                my $validate = sub {
                    my ($role, $initial) = @_;
                    my $object = $objects{$role};
                    die "missing assembly output: $object\n" unless -f $object && -s $object;
                    my $obj = bytes($object);
                    die "not ELF64 little-endian relocatable x86-64: $object\n"
                        unless length($obj) >= 64 && substr($obj, 0, 6) eq "\x7fELF\x02\x01" &&
                               unpack('v', substr($obj, 16, 2)) == 1 && unpack('v', substr($obj, 18, 2)) == 62;
                    if ($initial) {
                        my (undef, $elf) = $run->('validate-elf', $inputs{readelf}->{path}, '-hSWs', $object);
                        for my $symbol (@{$fixture->{symbols}}) {
                            die "missing output symbol $symbol\n" unless $elf =~ /\bGLOBAL\s+DEFAULT\s+(?!UND\b)\S+\s+\Q$symbol\E\s*$/m;
                        }
                        die "STT_FILE source mismatch\n" unless $elf =~ /\bFILE\s+LOCAL\s+DEFAULT\s+ABS\s+\Q$source\E\s*$/m;
                        $expected_object{$role} = $obj;
                    } else {
                        die "object drift: $id $role\n" unless $obj eq $expected_object{$role};
                    }
                    if ($mode ne 'bare') {
                        die "missing unsigned proof\n" unless -s $proofs{$role};
                        my $proof = bytes($proofs{$role});
                        my %fields;
                        for my $line (split /\n/, $proof) {
                            next unless $line =~ /^([a-z_0-9]+): (.*)$/;
                            die "duplicate proof field\n" if exists $fields{$1};
                            $fields{$1} = $2;
                        }
                        my $version = $profile{$role} eq 'compat' ? 2 : 3;
                        die "wrong proof version\n" unless $proof =~ /\Abasm attestation v$version\n/;
                        my %want = (source_path => $source, source_sha256 => $fixture->{sha256}, output_path => $object,
                            output_sha256 => sha256_hex($obj), tool_sha256 => $inputs{$role}->{sha256},
                            output_format => 'elf64', signature => 'unsigned', build_epoch => '0');
                        $want{target_profile} = $profile{$role} if $version == 3;
                        for my $key (keys %want) {
                            die "proof identity mismatch: $key\n" unless defined($fields{$key}) && $fields{$key} eq $want{$key};
                        }
                        if ($initial) { $expected_proof{$role} = $proof; }
                        else { die "proof drift: $id $role\n" unless $proof eq $expected_proof{$role}; }
                    } else { die "unexpected bare proof\n" if -e $proofs{$role}; }
                };
                for my $role (@roles) {
                    $run->('validation-assembly', @{$argv{$role}});
                    $validate->($role, 1);
                }
                die "candidate object mismatch: $id\n" if @roles == 2 && $expected_object{baseline} ne $expected_object{candidate};
                $case->{validation} = {object_equality => @roles == 2 ? 'BYTE_IDENTICAL' : 'SINGLE_TOOL_REPRODUCIBILITY',
                    proof_comparison => 'per-tool deterministic identity fields; never cross-tool proof equality',
                    semantics => 'ELF structure/symbol checks and byte parity, not execution or independent ISA proof'};
                for my $phase (['warmup', $warmups, $case->{warmups}], ['sample', $rounds, $case->{pairs}]) {
                    for my $round (0 .. $phase->[1] - 1) {
                        my @order = $round % 2 ? reverse(@roles) : @roles;
                        my $pair = {round => $round + 1, order => \@order, seconds => {}, command_ids => {}};
                        push @{$phase->[2]}, $pair;
                        for my $role (@order) {
                            unlink $objects{$role} or die "unlink own output: $!\n";
                            unlink $proofs{$role} or die "unlink own proof: $!\n" if $mode ne 'bare';
                            my ($elapsed, undef, $n) = $run->("$phase->[0]:$id:$round:$role", @{$argv{$role}});
                            $pair->{seconds}->{$role} = $elapsed;
                            $pair->{command_ids}->{$role} = $n;
                            $validate->($role, 0); # Clock has stopped; stale/no-op output cannot pass.
                        }
                    }
                }
                ($case->{statistics}, $case->{status}) = summarize($case->{pairs}, \@roles);
                for my $role (@roles) {
                    $case->{outputs}->{$role} = {object => identity($objects{$role})};
                    $case->{outputs}->{$role}->{proof} = identity($proofs{$role}) if $mode ne 'bare';
                }
            }
        }
        for my $role (@roles) {
            my (undef, $elf, $n) = $run->('inspect-measured-binary', $inputs{readelf}->{path}, '-hSWld', $inputs{$role}->{path});
            my %sections;
            for my $line (split /\n/, $elf) {
                $sections{$1} = hex($2) if $line =~ /^\s*\[\s*\d+\]\s+(\.\S+)\s+\S+\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)/;
            }
            $report->{binary_inspection}->{$role} = {command_id => $n, section_bytes => \%sections,
                runtime => $elf =~ /\bINTERP\b|\(NEEDED\)/ ? 'DYNAMIC_DEPENDENCIES_RECORDED_NOT_RESOLVED' : 'NO_INTERP_OR_NEEDED',
                compiler => 'NOT_AUTHENTICATED; object selection and current build rules are not an invocation receipt'};
        }
        if ($review) {
            # Selected, real static call sites only. Source/build-rule relation remains declared.
            my @maps = (
                {pilot => $inventory->{consumers}->[0]->{id}, role => 'host-bear',
                 object => "$root/toolchain/stage3/bear.o", final => "$root/toolchain/stage3/bear",
                 source => "$root/toolchain/stage3/bear.c", callers => [qw(bear_compile_file bear_preprocess_file)], provider => 'memchr'},
                {pilot => $inventory->{consumers}->[0]->{id}, role => 'host-bear-include',
                 object => "$root/toolchain/stage3/bear_pp.o", final => "$root/toolchain/stage3/bear",
                 source => "$root/toolchain/stage3/bear_pp.c", callers => ['bear_preprocess'], provider => 'memchr'});
            for my $role (@roles) {
                push @maps,
                    {pilot => $inventory->{consumers}->[1]->{id}, role => $role,
                     object => $inputs{"${role}_object"}->{path}, final => $inputs{$role}->{path},
                     source => "$root/toolchain/BearBasm/modules/01_foundation.inc",
                     callers => [qw(sym_find const_lookup macro_find pp_def_find)], provider => 'bear_memcmp'},
                    {pilot => $inventory->{consumers}->[2]->{id}, role => $role,
                     object => $inputs{"${role}_object"}->{path}, final => $inputs{$role}->{path},
                     source => "$root/toolchain/BearBasm/modules/06_attestation.inc",
                     callers => [qw(emit_basm_attestation basm_sha_file basm_sha_update)], provider => 'basm_sha_block'},
                    {pilot => $inventory->{consumers}->[2]->{id}, role => "$role-signing-not-timed",
                     object => "$root/toolchain/BearBasm/build/bear/sign.o", final => $inputs{$role}->{path},
                     source => "$root/toolchain/BearBasm/sign.c", callers => [qw(sign_finalise_attestation sgn_update)], provider => 'sgn_block'};
            }
            my %inspected;
            for my $map (@maps) {
                $map->{status} = 'STATIC_INSPECTION_ONLY';
                $map->{source_build_binding} = 'DECLARED_NOT_AUTHENTICATED';
                $map->{dynamic_call_distribution} = 'NOT_MEASURED';
                $map->{inspection_commands} = [];
                for my $path ($map->{object}, $map->{final}) {
                    if (!$inspected{$path}) {
                        for my $cmd (['nm', $inputs{nm}->{path}, '-a', $path],
                                     ['headers', $inputs{readelf}->{path}, '-hSWld', $path],
                                     ['relocations', $inputs{readelf}->{path}, '-rW', $path]) {
                            my ($kind, @argv) = @$cmd;
                            my (undef, $text, $n) = $run->('inspect-symbols-sections-relocations', @argv);
                            push @{$inspected{$path}->{ids}}, $n;
                            $inspected{$path}->{$kind} = $text;
                        }
                    }
                    push @{$map->{inspection_commands}}, @{$inspected{$path}->{ids}};
                }
                for my $path ($map->{object}, $map->{final}) {
                    for my $caller (@{$map->{callers}}, $map->{provider}) {
                        my $window;
                        if ($path eq $map->{final} && $map->{role} !~ /^host-bear/) {
                            $window = static_window($map->{object}, $map->{final}, $caller,
                                $map->{role} =~ /signing/ ? 'sign_finalise_attestation' : 'main', \%inspected);
                        }
                        my @selection = $window ? (sprintf('--start-address=0x%x', $window->{final_address}),
                            sprintf('--stop-address=0x%x', $window->{final_address} + $window->{length})) : ("--disassemble=$caller");
                        my (undef, $text, $n) = $run->('inspect-static-calls', $inputs{objdump}->{path},
                            $path eq $map->{object} ? '-dr' : '-d', @selection, $path);
                        push @{$map->{inspection_commands}}, $n;
                        push @{$map->{sites}}, {path => $path, symbol => $caller,
                            object_to_final_window => $window,
                            symbol_found => $text =~ /<\Q$caller\E>:/ ? JSON::PP::true : JSON::PP::false,
                            call_lines => [grep { /\bcall\b|R_X86_64_.*(?:memchr|memcmp|sha_|sgn_)/ } split /\n/, $text]};
                    }
                }
                push @{$report->{linkage}}, $map;
            }
        }
        for my $role (@roles) {
            my $snapshot = $report->{executable_snapshots}->{$role};
            $snapshot->{snapshot_after} = executable_snapshot($inputs{$role}, $snapshot->{snapshot_before}->{path}, $deadline, 0);
            die "snapshot identity drift: $role\n"
                unless $json->encode($snapshot->{snapshot_before}) eq $json->encode($snapshot->{snapshot_after});
            $snapshot->{status} = 'UNCHANGED';
        }
        my %after = map { $_ => identity($inputs{$_}->{path}) } keys %inputs;
        $report->{inputs_after} = \%after;
        die "identity drift before/after; discard performance interpretation\n" unless $json->encode(\%inputs) eq $json->encode(\%after);
        $report->{identity_status} = 'UNCHANGED';
        $report->{hardware}->{loadavg_after} = bytes('/proc/loadavg');
        die "total budget timeout\n" if clock_gettime(CLOCK_MONOTONIC) > $deadline;
        $report->{status} = (grep { $_->{status} ne 'STABLE' } @{$report->{cases}}) ? 'INCONCLUSIVE' : 'STABLE';
        1;
    };
    if (!$ok) {
        $report->{error} = $@;
        $report->{status} = 'REFUSED';
        $report->{evidence_kind} = 'INVALID_MEASUREMENT';
        warn $@;
    }
    $report->{elapsed_total_seconds} = clock_gettime(CLOCK_MONOTONIC) - $start;
    write_bytes("$dir/result.json", $json->encode($report));
    print "$report->{status}: $dir/result.json\n";
    return !$ok ? 1 : $report->{status} eq 'STABLE' ? 0 : 2;
}
unless (caller) {
    my $rc = eval { main() };
    if ($@) { warn $@; exit 1; }
    exit $rc;
}
1;
