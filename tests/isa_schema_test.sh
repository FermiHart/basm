#!/usr/bin/env bash
# INV-594: schema/oracle checks only; never execute assembled instruction bytes.
set -euo pipefail
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
exec perl - "$ROOT" <<'PERL'
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Copy qw(copy);
my ($root) = @ARGV;
ok(-f "$root/isa/generate.pl", 'checked-in ISA generator exists')
    or BAIL_OUT('IC03 schema generator is not implemented');
my $tmp = tempdir('basm-isa-XXXXXX', DIR => $ENV{TMPDIR} // '/tmp', CLEANUP => 1);
my $gen = "$root/isa/generate.pl";
my $serial = 0;
sub read_bytes {
    open my $fh, '<:raw', $_[0] or die "read $_[0]: $!";
    local $/;
    return <$fh> // '';
}
sub write_bytes {
    open my $fh, '>:raw', $_[0] or die "write $_[0]: $!";
    print {$fh} $_[1] or die "write: $!";
    close $fh or die "close: $!";
}
sub run {
    my @cmd = @_;
    my $log = "$tmp/run-" . ++$serial;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        open STDOUT, '>:raw', "$log.out" or die $!;
        open STDERR, '>:raw', "$log.err" or die $!;
        exec {$cmd[0]} @cmd;
        die "exec: $!";
    }
    waitpid($pid, 0);
    my $status = $?;
    return ($status, read_bytes("$log.out"), read_bytes("$log.err"));
}
my ($rc, $out, $err) = run($^X, $gen, '--check');
is($rc, 0, 'checked-in header and inventory are fresh') or BAIL_OUT($err);
my $source = read_bytes("$root/isa/forms.tsv");
my @lines = split /\n/, $source;
my @cols = split /\t/, $lines[0];
my @rows;
my %index;
for my $i (1..$#lines) {
    my %r;
    @r{@cols} = split /\t/, $lines[$i];
    $index{$r{id}} = $i;
    push @rows, \%r;
}
my %row = map { $_->{id} => $_ } @rows;
my @fixed = qw(nop pause ret leave cpuid rdtsc rdtscp rdmsr wrmsr syscall sysretq
    swapgs clc cld cli stc std sti clac stac clts hlt ud2 lfence mfence cdq cdqe
    cqo cwde fninit xgetbv xsetbv sfence);
my @expected_ids = (@fixed, (map { my $m = $_; map { "${m}_rr$_" } (8,16,32,64) }
    qw(mov add or and sub sbb xor cmp)), qw(adc_rr32 adc_rr64 rol_r32_8 ror_r64_1));
push @expected_ids, (map { my $m=$_; map { "${m}_$_" } qw(mr rm rr) } qw(movaps movups movdqa movdqu)),
    qw(movq_gx movq_mr movq_rm movq_xg paddd_rr paddq_rr pmuludq_rr por_rr pshufd_shuf pslld_shift psrld_shift punpckhqdq_rr punpcklqdq_rr pxor_rr);
# INV-782: scalar SSE moves/arithmetic/conversions for the stage2 FP bridge.
push @expected_ids, qw(addsd_rr cvtsd2ss_rr cvtsi2sd_xg cvtsi2ss_xg cvtss2sd_rr divsd_rr),
    (map { my $m=$_; map { "${m}_$_" } qw(mr rm rr) } qw(movsd movss)), qw(mulsd_rr subsd_rr);
is_deeply([sort keys %row], [sort @expected_ids], 'exact 109 forms including 40 bounded SSE forms with stable IDs');

my $header = read_bytes("$root/isa/intent_forms.h");
my $inventory = read_bytes("$root/isa/INVENTORY.md");
write_bytes("$tmp/minimal.tsv", "$lines[0]\n$lines[$index{nop}]\n");
($rc, $out, $err) = run($^X, $gen, '--schema', "$tmp/minimal.tsv", '--format', 'inventory');
ok(!$rc && $out =~ /1 forms: 1 fixed, 0 GPR register-register, 0 bounded GPR rotate, 0 bounded SSE/,
   'alternate bounded schemas report actual family counts');
for my $seed (0, 137) {
    local $ENV{PERL_HASH_SEED} = $seed;
    local $ENV{PERL_PERTURB_KEYS} = 2;
    local $ENV{LC_ALL} = $seed ? 'C.UTF-8' : 'C';
    local $ENV{SOURCE_DATE_EPOCH} = $seed;
    ($rc, $out, $err) = run($^X, $gen);
    ok(!$rc && $out eq $header && !$err, "deterministic header to stdout (seed $seed)");
    ($rc, $out, $err) = run($^X, $gen, '--format', 'inventory', '--output', "$tmp/inventory.md");
    ok(!$rc && !$out && !$err && read_bytes("$tmp/inventory.md") eq $inventory,
       "deterministic inventory to explicit output (seed $seed)");
}
($rc, $out, $err) = run($^X, $gen, '--output', "$tmp/header.h");
ok(!$rc && !$out && !$err && read_bytes("$tmp/header.h") eq $header, 'header --output agrees with stdout');
($rc, $out, $err) = run($^X, $gen, '--format', 'inventory');
ok(!$rc && $out eq $inventory && !$err, 'inventory stdout agrees with --output');
($rc, $out, $err) = run($^X, $gen, '--check', '--output', "$tmp/forbidden");
ok($rc && !-e "$tmp/forbidden", '--check refuses output and creates nothing');

# Isolated generator copy: test both stale and missing artifacts without touching the worktree.
mkdir "$tmp/isa" or die $!;
copy("$root/isa/$_", "$tmp/isa/$_") or die $! for qw(generate.pl forms.tsv intent_forms.h INVENTORY.md);
for my $file ('intent_forms.h', 'INVENTORY.md') {
    my $path = "$tmp/isa/$file";
    my $good = read_bytes($path);
    write_bytes($path, "stale\n");
    ($rc, $out, $err) = run($^X, "$tmp/isa/generate.pl", '--check');
    ok($rc && $err =~ /stale \Q$file\E/ && read_bytes($path) eq "stale\n", "$file drift rejected, not repaired");
    unlink $path or die $!;
    ($rc, $out, $err) = run($^X, "$tmp/isa/generate.pl", '--check');
    ok($rc && !-e $path, "$file missing rejected, not created");
    write_bytes($path, $good);
}

sub field_change {
    my ($id, $column, $value) = @_;
    my @changed = @lines;
    my @fields = split /\t/, $changed[$index{$id}];
    my ($n) = grep { $cols[$_] eq $column } 0..$#cols;
    $fields[$n] = $value;
    $changed[$index{$id}] = join("\t", @fields);
    return join("\n", @changed) . "\n";
}
my @bad = (
    ['header order', join("\t", reverse @cols) . "\n$lines[1]\n", qr/header/],
    ['empty schema', '', qr/final LF/],
    ['header only', "$lines[0]\n", qr/1\.\.1024 forms/],
    ['missing final LF', substr($source, 0, -1), qr/final LF/],
    ['blank row', "$source\n", qr/12 fields/],
    ['extra field', "$source$lines[1]\textra\n", qr/12 fields/],
    ['missing field', "$source" . join("\t", ('x') x 11) . "\n", qr/12 fields/],
    ['row bound', "$source" . ("$lines[1]\n" x 1024), qr/1\.\.1024 forms/],
    ['input bound', 'x' x 1048577, qr/exceeds 1048576/],
    ['line bound', "$source" . ('x' x 1025) . "\n", qr/line exceeds/],
);
for my $case (
    ['id uppercase', 'nop', 'id', 'Nop', qr/lowercase id/],
    ['id punctuation', 'nop', 'id', 'no-p', qr/lowercase id/],
    ['id bound', 'nop', 'id', 'n' x 65, qr/lowercase id/],
    ['duplicate id', 'pause', 'id', 'nop', qr/duplicate id/],
    ['mnemonic unknown', 'nop', 'mnemonic', 'nopp', qr/unknown mnemonic/],
    ['mnemonic case', 'nop', 'mnemonic', 'NOP', qr/unknown mnemonic/],
    ['mode', 'nop', 'mode', '32', qr/mode must/],
    ['encoding', 'nop', 'encoding', 'memory', qr/invalid encoding/],
    ['width', 'add_rr8', 'width', '7', qr/invalid width/],
    ['width spelling', 'add_rr8', 'width', '08', qr/invalid width/],
    ['fixed width', 'nop', 'width', '8', qr/invalid fixed form/],
    ['RR width zero', 'add_rr8', 'width', '0', qr/invalid gpr_rr form/],
    ['RR width 128', 'add_rr8', 'width', '128', qr/invalid gpr_rr form/],
    ['fixed operands', 'nop', 'operands', 'gpr,gpr', qr/invalid fixed form/],
    ['RR operands', 'add_rr8', 'operands', 'gpr,mem', qr/invalid gpr_rr form/],
    ['fixed family', 'nop', 'mnemonic', 'mov', qr/invalid fixed form/],
    ['RR family', 'mov_rr8', 'mnemonic', 'nop', qr/invalid gpr_rr form/],
    ['opcode hex', 'nop', 'opcode', 'gg', qr/opcode must/],
    ['opcode case', 'nop', 'opcode', '0F', qr/opcode must/],
    ['opcode spacing', 'nop', 'opcode', '0f  05', qr/opcode must/],
    ['opcode bound', 'nop', 'opcode', '01 02 03 04 05', qr/opcode must/],
    ['RR opcode length', 'add_rr8', 'opcode', '00 01', qr/invalid gpr_rr form/],
    ['ADC width', 'adc_rr32', 'width', '16', qr/adc supports only/],
    ['ADC opcode', 'adc_rr32', 'opcode', '10', qr/adc supports only/],
    ['ROR width', 'ror_r64_1', 'width', '32', qr/bounded gpr_rotate/],
    ['ROL width', 'rol_r32_8', 'width', '64', qr/bounded gpr_rotate/],
    ['ROR count zero', 'ror_r64_1', 'operands', 'gpr,0', qr/bounded gpr_rotate/],
    ['ROR count 63', 'ror_r64_1', 'operands', 'gpr,63', qr/bounded gpr_rotate/],
    ['ROL count one', 'rol_r32_8', 'operands', 'gpr,1', qr/bounded gpr_rotate/],
    ['ROL count CL', 'rol_r32_8', 'operands', 'gpr,cl', qr/bounded gpr_rotate/],
    ['rotate opcode', 'ror_r64_1', 'opcode', 'c1', qr/bounded gpr_rotate/],
    ['rotate memory', 'ror_r64_1', 'operands', 'mem,1', qr/bounded gpr_rotate/],
    ['SSE opcode', 'paddd_rr', 'opcode', '66 0f fc', qr/bounded SSE/],
    ['SSE width', 'paddd_rr', 'width', '64', qr/bounded SSE/],
    ['SSE memory arithmetic', 'paddd_rr', 'operands', 'xmm,mem', qr/bounded SSE/],
    ['SSE destructive read', 'paddd_rr', 'reads', 'src', qr/bounded SSE/],
    ['SSE move read', 'movdqu_rr', 'reads', 'dst,src', qr/bounded SSE/],
    ['SSE memory read', 'movdqu_rm', 'reads', 'src', qr/bounded SSE/],
    ['SSE memory write', 'movdqu_mr', 'writes', 'dst', qr/bounded SSE/],
    ['SSE flags', 'pxor_rr', 'flags', 'zf:write', qr/bounded SSE/],
    ['SSE feature', 'paddd_rr', 'features', 'base', qr/bounded SSE/],
    ['SSE control', 'paddd_rr', 'control', 'return', qr/bounded SSE/],
    ['feature unknown', 'nop', 'features', 'ssee2', qr/invalid features/],
    ['feature duplicate', 'nop', 'features', 'sse2,sse2', qr/unique and sorted/],
    ['feature order', 'nop', 'features', 'xsave,sse2', qr/unique and sorted/],
    ['feature none', 'nop', 'features', 'none', qr/nonempty/],
    ['feature base mix', 'nop', 'features', 'base,sse2', qr/stand alone/],
    ['RR feature', 'mov_rr8', 'features', 'sse2', qr/requires base/],
    ['control unknown', 'nop', 'control', 'safe', qr/invalid control/],
    ['RR control', 'mov_rr8', 'control', 'return', qr/next control/],
    ['effect unknown', 'nop', 'reads', 'everything', qr/invalid reads/],
    ['effect duplicate', 'add_rr8', 'reads', 'src,src', qr/unique and sorted/],
    ['effect order', 'add_rr8', 'reads', 'src,dst', qr/unique and sorted/],
    ['fixed placeholder', 'nop', 'reads', 'dst', qr/operand placeholders/],
    ['flag action', 'clc', 'flags', 'cf:preserve', qr/invalid flags/],
    ['flag duplicate', 'clc', 'flags', 'cf:one,cf:zero', qr/duplicate flag/],
    ['flag intersection', 'clc', 'writes', 'none', qr/flag intersection/],
    ['aggregate action', 'syscall', 'flags', 'rflags:zero', qr/must be unknown/],
    ['aggregate mixed', 'syscall', 'flags', 'cf:zero,rflags:unknown', qr/cannot be mixed/],
    ['empty field', 'nop', 'reads', '', qr/1\.\.192 bytes/],
    ['field bound', 'nop', 'reads', 'x' x 193, qr/1\.\.192 bytes/],
    ['pipe', 'nop', 'reads', 'none|other', qr/pipes are forbidden/],
    ['nonascii', 'nop', 'reads', "\xff", qr/ASCII/],
    ['NUL', 'nop', 'reads', "\x00", qr/ASCII/],
    ['CRLF', 'nop', 'mode', "64\r", qr/ASCII/],
    ['quote injection', 'nop', 'reads', '"bad"', qr/invalid reads/],
) {
    my ($name, $id, $column, $value, $pattern) = @$case;
    push @bad, [$name, field_change($id, $column, $value), $pattern];
}
my @swapped = @lines;
@swapped[1,2] = @swapped[2,1];
push @bad, ['row order', join("\n", @swapped) . "\n", qr/sorted by mnemonic/];
my $duplicate = $lines[1];
$duplicate =~ s/^[^\t]+\t/another_id\t/;
push @bad, ['duplicate form', "$lines[0]\n$lines[1]\n$duplicate\n", qr/duplicate form/];
for my $case (@bad) {
    my ($name, $text, $pattern) = @$case;
    write_bytes("$tmp/bad.tsv", $text);
    write_bytes("$tmp/untouched", 'sentinel');
    ($rc, $out, $err) = run($^X, $gen, '--schema', "$tmp/bad.tsv", '--output', "$tmp/untouched");
    ok($rc && !$out && $err =~ $pattern && length($err) <= 200
       && read_bytes("$tmp/untouched") eq 'sentinel', "reject $name, bounded error, output untouched")
       or diag($err);
}
write_bytes("$tmp/isa/forms.tsv", field_change('nop', 'opcode', '91'));
($rc, $out, $err) = run($^X, "$tmp/isa/generate.pl", '--check');
ok($rc && $err =~ /stale intent_forms.h/ && read_bytes("$tmp/isa/intent_forms.h") eq $header,
   'well-formed schema drift rejected by --check without rewriting');
write_bytes("$tmp/isa/forms.tsv", field_change('nop', 'id', 'BAD'));
($rc, $out, $err) = run($^X, "$tmp/isa/generate.pl", '--check');
ok($rc && $err =~ /lowercase id/ && read_bytes("$tmp/isa/intent_forms.h") eq $header
   && read_bytes("$tmp/isa/INVENTORY.md") eq $inventory, 'malformed --check leaves both artifacts untouched');

# Compile only a host metadata dumper, not basm or any generated machine bytes.
write_bytes("$tmp/api.c", <<'C');
#include "intent_forms.h"
#include "intent_forms.h"
#include <stdio.h>
typedef char constants[(INTENT_FIXED == 0 && INTENT_GPR_RR == 1 && INTENT_GPR_ROTATE == 2) ? 1 : -1];
typedef char count_matches[(sizeof(g_intent_forms) / sizeof(g_intent_forms[0]) == INTENT_FORM_COUNT) ? 1 : -1];
int main(void) {
    int i, j;
    const char *encodings[]={"fixed","gpr_rr","gpr_rotate","sse_rr","sse_rm","sse_mr","sse_xg","sse_gx","sse_shift","sse_shuf"};
    for (i = 0; i < INTENT_FORM_COUNT; ++i) {
        const struct IntentForm *f = &g_intent_forms[i];
        const IntentForm *same_type = f;
        if (f->opcode_len < 1 || f->opcode_len > 4 || same_type != f) return 1;
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t", f->id, f->mnemonic,
               f->operands, f->reads, f->writes, f->flags, f->features, f->control);
        for (j = 0; j < f->opcode_len; ++j) printf("%s%02x", j ? " " : "", f->opcode[j]);
        for (; j < 4; ++j) if (f->opcode[j]) return 2;
        if (f->encoding < 0 || f->encoding > INTENT_SSE_SHUF) return 3;
        printf("\t%d\t%s\t64\n", f->width, encodings[f->encoding]);
    }
    return 0;
}
C
($rc, $out, $err) = run($ENV{HOST_CC} // 'cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-pedantic',
    '-I', "$root/isa", "$tmp/api.c", '-o', "$tmp/api");
is($rc, 0, 'header compiles standalone, guarded, with exact API constants/count') or BAIL_OUT($err);
($rc, $out, $err) = run("$tmp/api");
ok(!$rc && !$err && $out eq join("\n", @lines[1..$#lines]) . "\n", 'C metadata round-trips all TSV rows and opcode padding');

# Independent expected metadata and real set intersections, not a claim of semantics.
my %flag_names = map { $_ => 1 } qw(ac af cf df if of pf rflags sf zf);
my $arith = 'af:write,cf:write,of:write,pf:write,sf:write,zf:write';
my $logic = 'af:undefined,cf:zero,of:zero,pf:write,sf:write,zf:write';
my %fixed_flags = (clac=>'ac:zero', stac=>'ac:one', clc=>'cf:zero', stc=>'cf:one',
    cld=>'df:zero', std=>'df:one', cli=>'if:zero', sti=>'if:one',
    syscall=>'rflags:unknown', sysretq=>'rflags:unknown');
my %features = (cpuid=>'cpuid', rdtsc=>'tsc', rdtscp=>'rdtscp', rdmsr=>'msr', wrmsr=>'msr',
    clac=>'smap', stac=>'smap', lfence=>'sse2', mfence=>'sse2', sfence=>'sse', syscall=>'syscall',
    sysretq=>'syscall', fninit=>'x87', xgetbv=>'xsave', xsetbv=>'xsave');
$features{$_}='sse2' for qw(movdqa movdqu movq paddd paddq pmuludq por pshufd pslld psrld punpckhqdq punpcklqdq pxor);
# INV-782: scalar SSE forms of the stage2 FP bridge.
$features{$_}='sse2' for qw(addsd subsd cvtsd2ss cvtsi2sd cvtsi2ss cvtss2sd divsd movsd movss mulsd);
$features{$_}='sse' for qw(movaps movups);
my %controls = (ret=>'return', syscall=>'system', sysretq=>'system', hlt=>'halt', ud2=>'trap',
    cpuid=>'barrier', rdtscp=>'barrier', lfence=>'barrier', mfence=>'barrier', sfence=>'barrier');
my @metadata_errors;
for my $r (@rows) {
    my $m = $r->{mnemonic};
    my @declared = sort map { (split /:/)[0] } grep { $_ ne 'none' } split /,/, $r->{flags};
    my @intersection = sort grep { $flag_names{$_} } split /,/, $r->{writes};
    push @metadata_errors, "$r->{id}: flags intersection" unless "@declared" eq "@intersection";
    my $expected_flags = $fixed_flags{$m} // ($m =~ /^(adc|add|sub|sbb|cmp)$/ ? $arith
        : $m =~ /^(and|or|xor)$/ ? $logic : $m eq 'ror' ? 'cf:write,of:write'
        : $m eq 'rol' ? 'cf:write,of:undefined' : 'none');
    push @metadata_errors, "$r->{id}: flags actions" unless $r->{flags} eq $expected_flags;
    push @metadata_errors, "$r->{id}: feature" unless $r->{features} eq ($features{$m} // 'base');
    push @metadata_errors, "$r->{id}: control" unless $r->{control} eq ($controls{$m} // 'next');
    if ($r->{encoding} eq 'gpr_rr') {
        my $reads = $m eq 'mov' ? 'src' : $m =~ /^(adc|sbb)$/ ? 'cf,dst,src' : 'dst,src';
        my $writes = $m eq 'mov' ? 'dst' : $m eq 'cmp' ? 'af,cf,of,pf,sf,zf' : 'af,cf,dst,of,pf,sf,zf';
        push @metadata_errors, "$r->{id}: RR read/write set" unless $r->{reads} eq $reads && $r->{writes} eq $writes;
    } elsif ($r->{encoding} eq 'gpr_rotate') {
        push @metadata_errors, "$r->{id}: rotate read/write set"
            unless $r->{reads} eq 'dst' && $r->{writes} eq 'cf,dst,of';
    }
}
is_deeply(\@metadata_errors, [], 'all 109 declared flag intersections/actions, GPR effects, features and controls match expectations');
for my $id (qw(cpuid rdtsc rdtscp rdmsr wrmsr syscall sysretq swapgs clac stac clts cli sti hlt ud2 lfence mfence fninit pause xgetbv xsetbv)) {
    ok($row{$id}{reads} =~ /\bsystem\.unknown\b/ && $row{$id}{writes} =~ /\bsystem\.unknown\b/,
       "$id retains opaque system effects");
}
ok($row{ret}{reads} =~ /memory\.stack/ && $row{leave}{reads} =~ /memory\.stack/,
   'no-operand RET/LEAVE do not pretend to be memory-free');
is_deeply([map { [$row{$_}{reads}, $row{$_}{writes}] } qw(cdq cdqe cqo cwde)],
    [['eax','edx'], ['eax','rax'], ['rax','rdx'], ['ax','eax']], 'sign-extension implicit registers are explicit');

my @vectors;
my %samples = (
    8 => [[qw(al cl),0,1,0], [qw(r8b r15b),8,15,0], [qw(spl dil),4,7,1],
          [qw(ah bh),4,7,0], [qw(al r9b),0,9,0], [qw(r10b dl),10,2,0], [qw(al al),0,0,0]],
    16 => [[qw(ax cx),0,1,0], [qw(r8w r15w),8,15,0], [qw(ax r9w),0,9,0], [qw(r10w dx),10,2,0], [qw(ax ax),0,0,0]],
    32 => [[qw(eax ecx),0,1,0], [qw(r8d r15d),8,15,0], [qw(eax r9d),0,9,0], [qw(r10d edx),10,2,0], [qw(eax eax),0,0,0]],
    64 => [[qw(rax rcx),0,1,0], [qw(r8 r15),8,15,0], [qw(rax r9),0,9,0], [qw(r10 rdx),10,2,0], [qw(rax rax),0,0,0]],
);
for my $r (@rows) {
    if ($r->{encoding} eq 'fixed') {
        # NASM's unambiguous spelling for the REX.W SYSRET form.
        my $asm = $r->{mnemonic} eq 'sysretq' ? 'o64 sysret' : $r->{mnemonic};
        (my $hex = $r->{opcode}) =~ s/ //g;
        push @vectors, [$r->{id}, $asm, pack('H*', $hex)];
    } elsif ($r->{encoding} eq 'gpr_rotate') {
        for my $s (@{$samples{$r->{width}}}) {
            my ($dst, undef, $d) = @$s;
            my $ror = $r->{mnemonic} eq 'ror';
            my $rex = 0x40 | (($r->{width} == 64) << 3) | ($d >= 8);
            my @bytes = ($rex != 0x40 ? ($rex) : (), $ror ? 0xd1 : 0xc1,
                         0xc0 | ($ror ? 8 : 0) | ($d & 7), $ror ? () : (8));
            push @vectors, ["$r->{id} $dst", "$r->{mnemonic} $dst," . ($ror ? 1 : 8), pack('C*', @bytes)];
        }
    } elsif ($r->{encoding} =~ /^sse_/) {
        my $e=$r->{encoding};
        my $m=$r->{mnemonic};
        my $ops=$e eq 'sse_mr' ? '[r13+128],xmm15' : $e eq 'sse_rm' ? 'xmm15,[r13+128]'
            : $e eq 'sse_xg' ? 'xmm15,r8' : $e eq 'sse_gx' ? 'r15,xmm8'
            : $e eq 'sse_shift' ? 'xmm15,16' : $e eq 'sse_shuf' ? 'xmm15,xmm8,50' : 'xmm15,xmm8';
        my @op=map { hex($_) } split / /, $r->{opcode};
        my @bytes;
        push @bytes, shift @op if $op[0]!=0x0f;
        push @bytes, $e =~ /^sse_[xg][gx]$/ ? 0x4d : $e eq 'sse_shift' ? 0x41 : 0x45;
        push @bytes, @op;
        push @bytes, $e =~ /^sse_(?:mr|rm)$/ ? (0xbd,128,0,0,0) : $e eq 'sse_gx' ? 0xc7
            : $e eq 'sse_shift' ? ($m eq 'pslld' ? 0xf7 : 0xd7) : 0xf8;
        push @bytes, 16 if $e eq 'sse_shift';
        push @bytes, 50 if $e eq 'sse_shuf';
        push @vectors, [$r->{id}, "$m $ops", pack('C*', @bytes)];
    } else {
        for my $s (@{$samples{$r->{width}}}) {
            my ($dst, $src, $d, $sreg, $force) = @$s;
            my @bytes;
            push @bytes, 0x66 if $r->{width} == 16;
            my $rex = 0x40 | (($r->{width} == 64) << 3) | (($sreg >= 8) << 2) | ($d >= 8);
            push @bytes, $rex if $rex != 0x40 || $force;
            push @bytes, hex($r->{opcode}), 0xc0 | (($sreg & 7) << 3) | ($d & 7);
            push @vectors, ["$r->{id} $dst,$src", "$r->{mnemonic} $dst,$src", pack('C*', @bytes)];
        }
    }
}
write_bytes("$tmp/oracle.asm", "BITS 64\n" . join('', map { "$_->[1]\n" } @vectors));
($rc, $out, $err) = run($ENV{NASM} // 'nasm', '-f', 'bin', '-o', "$tmp/oracle.bin", "$tmp/oracle.asm");
is($rc, 0, 'NASM assembles all fixed and RR samples (never executed)') or BAIL_OUT($err);
my $oracle = read_bytes("$tmp/oracle.bin");
my $offset = 0;
for my $v (@vectors) {
    is(unpack('H*', substr($oracle, $offset, length($v->[2]))), unpack('H*', $v->[2]), "NASM bytes: $v->[0]");
    $offset += length($v->[2]);
}
is(length($oracle), $offset, 'oracle has no unaccounted bytes');
diag('Encoding/declared-metadata evidence only; no machine bytes executed, no semantic proof.');
done_testing();
PERL
