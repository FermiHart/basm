#!/usr/bin/env perl
use strict;
use warnings;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use File::Basename qw(dirname);
use File::Spec;
use Getopt::Long qw(GetOptions Configure);
use JSON::PP;

Configure(qw(no_auto_abbrev no_ignore_case));
my ($root, $basm, $lane, $flags, $help);
my (@artifacts, @tools);
GetOptions('repo-root=s' => \$root, 'basm=s' => \$basm,
           'artifact=s@' => \@artifacts, 'tool=s@' => \@tools,
           'lane=s' => \$lane, 'build-flags=s' => \$flags, 'help' => \$help)
    or die "usage: perl evidence.pl --help\n";
die "unexpected positional arguments; use --help\n" if @ARGV;
if ($help) {
    print <<'HELP';
Usage: perl lab/evidence.pl --basm PATH --artifact ID=PATH [options]

Read-only IC02 identity collector; canonical JSON goes to stdout.
  --repo-root PATH     Beyond source root (default: relative to this script)
  --basm PATH          Explicit readable executable; never searched on PATH
  --artifact ID=PATH   Existing nonempty object/proof/library/etc.; repeatable
  --tool ID=PATH       Additional existing executable to identify, not invoke
  --lane LABEL         Caller-declared compiler/runtime lane, not verified
  --build-flags TEXT   Caller-declared build flags, not inferred from Makefiles
  --help               This help; no basm or artifact required

Requires host Perl with core Digest::SHA and JSON::PP. No subprocesses,
builds, clocks, timing, signing, candidate execution or performance claims.
Missing paths/tools, empty artifacts, duplicate IDs and corpus drift refuse
before any JSON is emitted. Same bytes, paths and declarations give the same
manifest. Hashes do NOT prove build provenance, linkage or budget approval.
HELP
    exit 0;
}
die "--basm is required\n" unless defined $basm;
die "at least one --artifact ID=PATH is required\n" unless @artifacts;
my $script = abs_path(__FILE__);
my $lab = dirname($script);
$root //= "$lab/../../..";
die "missing repo root: $root\n" unless -d $root;
$root = abs_path($root);
my $json = JSON::PP->new->canonical->pretty;

# INV-590: identify bytes without executing tools or treating hashes as proof.
sub identity {
    my ($path, $role, $executable) = @_;
    die "invalid $role path\n" if !defined($path) || $path eq '' || $path =~ /[\x00-\x1f\x7f]/;
    $path = File::Spec->rel2abs($path);
    die "missing or unreadable $role: $path\n" unless -f $path && -r $path;
    die "$role not executable: $path\n" if $executable && !-x $path;
    my $resolved = abs_path($path);
    open my $f, '<:raw', $path or die "open $role $path: $!\n";
    my @before = stat($f);
    die "empty $role: $path\n" unless $before[7];
    my $sha = Digest::SHA->new(256)->addfile($f)->hexdigest;
    my @after = stat($f);
    close $f or die "close $role $path: $!\n";
    my @current = stat($path);
    for my $i (0, 1, 7, 9, 10) {
        die "$role changed while reading: $path\n"
            unless defined $current[$i] && $before[$i] == $after[$i] && $before[$i] == $current[$i];
    }
    return {path => $path, resolved_path => $resolved, bytes => 0 + $before[7], sha256 => $sha};
}
sub read_bytes {
    open my $f, '<:raw', $_[0] or die "read $_[0]: $!\n";
    local $/;
    return scalar(<$f>) // '';
}
sub repo_path {
    my ($relative) = @_;
    die "invalid inventory path\n" unless defined $relative &&
        $relative =~ m{\A[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\z} &&
        $relative !~ m{(?:\A|/)\.\.?(?:/|\z)};
    return "$root/$relative";
}
sub named_identities {
    my ($role, @specs) = @_;
    my %entries;
    for my $spec (@specs) {
        my ($id, $path) = $spec =~ /\A([a-zA-Z0-9][a-zA-Z0-9_.-]*)=(.+)\z/s;
        die "invalid --$role ID=PATH: $spec\n" unless defined $id;
        die "duplicate $role ID: $id\n" if exists $entries{$id};
        $entries{$id} = identity($path, "$role $id", $role eq 'tool');
    }
    return \%entries;
}
my $tool_ids = named_identities('tool', "basm=$basm", "perl=$^X", @tools);
my $artifact_ids = named_identities('artifact', @artifacts);
my $inventory_id = identity("$lab/inventory-v1.json", 'inventory', 0);
my $inventory_bytes = read_bytes($inventory_id->{path});
die "inventory changed while reading\n" unless sha256_hex($inventory_bytes) eq $inventory_id->{sha256};
my $inventory = decode_json($inventory_bytes);
die "unsupported inventory schema\n" unless $inventory->{schema} eq 'BASM-IC02-INVENTORY-v1';
my @sources;
for my $source (@{$inventory->{source_evidence}}) {
    my $id = identity(repo_path($source->{path}), 'consumer source', 0);
    my $bytes = read_bytes($id->{path});
    die "source changed while reading: $source->{path}\n" unless sha256_hex($bytes) eq $id->{sha256};
    for my $anchor (@{$source->{anchors}}) {
        die "source anchor drift: $source->{path}: $anchor\n" if index($bytes, $anchor) < 0;
    }
    push @sources, {%$source, identity => $id};
}
my @fixtures;
my %fixture_ids;
for my $fixture (@{$inventory->{workload}->{fixtures}}) {
    die "duplicate corpus ID: $fixture->{id}\n" if $fixture_ids{$fixture->{id}}++;
    my $id = identity(repo_path($fixture->{path}), "corpus $fixture->{id}", 0);
    die "corpus checksum drift: $fixture->{path}\n" unless $id->{sha256} eq $fixture->{sha256};
    push @fixtures, {%$fixture, identity => $id};
}
# The content ID excludes checkout locations, but binds order, roles and paths.
my $workload_sha = sha256_hex($json->encode($inventory->{workload}));
my $manifest = {
    schema => 'BASM-IC02-EVIDENCE-v1', evidence_kind => 'IDENTITY_ONLY',
    ic02_status => 'GROUNDWORK_ONLY', measurements => undef, linkage => 'UNPROVEN',
    repo_root => $root, tools => $tool_ids, artifacts => $artifact_ids,
    collector => identity($script, 'collector', 0), inventory => $inventory_id,
    perl_version => "$^V",
    stdlib => { 'Digest::SHA' => identity($INC{'Digest/SHA.pm'}, 'Digest::SHA', 0),
                'JSON::PP' => identity($INC{'JSON/PP.pm'}, 'JSON::PP', 0) },
    lane => { status => defined($lane) ? 'DECLARED' : 'UNSPECIFIED',
              compiler_runtime => $lane, build_flags => $flags, provenance => 'UNPROVEN' },
    consumers => $inventory->{consumers}, source_evidence => \@sources,
    workload => {%{$inventory->{workload}}, sha256 => $workload_sha, fixtures => \@fixtures},
    budgets => $inventory->{budgets},
    gaps => [
        'No baseline, paired timings, dispersion, cold/warm cache or hardware measurements.',
        'New budgets and search time/round limits are not ratified; IC03 remains blocked on IC02.',
        'Object-to-source and final symbol/provider linkage are not verified; artifact IDs are caller labels.',
        'No compiler invocation receipt or complete tool/runtime dependency closure is established.',
        'No candidate or assembled instructions are executed; no correctness or cryptographic proof is inferred.',
        'Small L1/L2 corpus is not all L1-L10 workloads or a frozen Bear NUL-scan input distribution.',
        'No Beyond boot gate is performed by this collector.'
    ]
};
print $json->encode($manifest) or die "write manifest: $!\n";
close STDOUT or die "close manifest: $!\n";
