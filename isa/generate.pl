#!/usr/bin/env perl
# Author: F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($Bin);
use Getopt::Long qw(GetOptions Configure);
use Digest::SHA qw(sha256_hex);

# INV-594: validate the entire bounded schema before producing any output.
my ($schema, $output, $format, $check, $help);
Configure(qw(no_auto_abbrev no_ignore_case));
GetOptions('schema=s' => \$schema, 'output=s' => \$output,
           'format=s' => \$format, 'check' => \$check, 'help' => \$help)
    or die "isa: invalid options (see --help)\n";
die "isa: unexpected argument\n" if @ARGV;
if ($help) {
    print "Usage: perl isa/generate.pl [--schema FILE] [--format header|inventory] [--output FILE]\n",
          "       perl isa/generate.pl [--schema FILE] --check\n",
          "Default: header to stdout. --check reads both checked-in artifacts, never writes.\n";
    exit 0;
}
die "isa: --check cannot be combined with --output or --format\n"
    if $check && (defined $output || defined $format);
$schema //= "$Bin/forms.tsv";
$format //= 'header';
die "isa: invalid format\n" unless $format eq 'header' || $format eq 'inventory';

my $line_no = 0;
sub refuse { die "isa schema line $line_no: $_[0]\n"; }
sub read_bytes {
    my ($path) = @_;
    open my $fh, '<:raw', $path or refuse('cannot read input');
    my $data = '';
    while (1) {
        my $n = read($fh, my $chunk, 8192);
        refuse('input read failed') unless defined $n;
        last unless $n;
        $data .= $chunk;
        refuse('input exceeds 1048576 bytes') if length($data) > 1048576;
    }
    close $fh or refuse('input close failed');
    return $data;
}
sub token_list {
    my ($text, $allowed, $field) = @_;
    return () if $text eq 'none';
    my @items = split /,/, $text, -1;
    my $last = '';
    for my $item (@items) {
        refuse("invalid $field token") unless $allowed->{$item};
        refuse("$field tokens must be unique and sorted") unless $item gt $last;
        $last = $item;
    }
    return @items;
}

my @columns = qw(id mnemonic operands reads writes flags features control opcode width encoding mode);
my %fixed = map { $_ => 1 } qw(nop pause ret leave cpuid rdtsc rdtscp rdmsr wrmsr
    syscall sysretq swapgs clc cld cli stc std sti clac stac clts hlt ud2 lfence
    mfence sfence cdq cdqe cqo cwde fninit xgetbv xsetbv);
my %rr = map { $_ => 1 } qw(mov adc add or and sub sbb xor cmp);
my %rotate = (rol => '32:gpr,8:c1', ror => '64:gpr,1:d1'); # INV-730: closed forms, not arbitrary immediates.
# INV-740: exact operand/opcode/effect tuples, not an extensible ISA escape hatch.
my %sse;
for my $m (qw(movaps movups movdqa movdqu)) {
    my ($load, $store) = $m eq 'movaps' ? ('0f 28', '0f 29') : $m eq 'movups' ? ('0f 10', '0f 11')
        : $m eq 'movdqa' ? ('66 0f 6f', '66 0f 7f') : ('f3 0f 6f', 'f3 0f 7f');
    $sse{"$m:sse_rr"} = "128:xmm,xmm:$load:src:dst";
    $sse{"$m:sse_rm"} = "128:xmm,mem:$load:memory,src.address:dst";
    $sse{"$m:sse_mr"} = "128:mem,xmm:$store:dst.address,src:memory";
}
for my $pair ([paddd=>'fe'], [paddq=>'d4'], [pxor=>'ef'], [por=>'eb'], [pmuludq=>'f4'],
              [punpcklqdq=>'6c'], [punpckhqdq=>'6d']) {
    $sse{"$pair->[0]:sse_rr"} = "128:xmm,xmm:66 0f $pair->[1]:dst,src:dst";
}
$sse{'movq:sse_rm'} = '64:xmm,mem:f3 0f 7e:memory,src.address:dst';
$sse{'movq:sse_mr'} = '64:mem,xmm:66 0f d6:dst.address,src:memory';
$sse{'movq:sse_xg'} = '64:xmm,gpr:66 0f 6e:src:dst';
$sse{'movq:sse_gx'} = '64:gpr,xmm:66 0f 7e:src:dst';
$sse{"$_:sse_shift"} = '128:xmm,imm8:66 0f 72:dst:dst' for qw(pslld psrld);
$sse{'pshufd:sse_shuf'} = '128:xmm,xmm,imm8:66 0f 70:src:dst';
# INV-782: scalar SSE moves/arithmetic/conversions for the stage2 FP bridge.
# movsd is fully modeled here (enc_sse resolves the form by mnemonic), but it
# is EXCLUDED from INTENT_SSE_NAMES: the bare name is the legacy string op and
# its dispatch lives in the INSN_movsd case, which routes operand forms here.
$sse{'movsd:sse_rr'} = '64:xmm,xmm:f2 0f 10:src:dst';
$sse{'movsd:sse_rm'} = '64:xmm,mem:f2 0f 10:memory,src.address:dst';
$sse{'movsd:sse_mr'} = '64:mem,xmm:f2 0f 11:dst.address,src:memory';
$sse{'movss:sse_rr'} = '64:xmm,xmm:f3 0f 10:src:dst';
$sse{'movss:sse_rm'} = '64:xmm,mem:f3 0f 10:memory,src.address:dst';
$sse{'movss:sse_mr'} = '64:mem,xmm:f3 0f 11:dst.address,src:memory';
$sse{'addsd:sse_rr'} = '64:xmm,xmm:f2 0f 58:dst,src:dst';
# INV-BIRBOOT-CURRENT-001: real SUBSD, preserving signed-zero and NaN behavior.
$sse{'subsd:sse_rr'} = '64:xmm,xmm:f2 0f 5c:dst,src:dst';
$sse{'mulsd:sse_rr'} = '64:xmm,xmm:f2 0f 59:dst,src:dst';
$sse{'divsd:sse_rr'} = '64:xmm,xmm:f2 0f 5e:dst,src:dst';
$sse{'cvtsd2ss:sse_rr'} = '64:xmm,xmm:f2 0f 5a:dst,src:dst';
$sse{'cvtss2sd:sse_rr'} = '64:xmm,xmm:f3 0f 5a:dst,src:dst';
$sse{'cvtsi2sd:sse_xg'} = '64:xmm,gpr:f2 0f 2a:src:dst';
$sse{'cvtsi2ss:sse_xg'} = '64:xmm,gpr:f3 0f 2a:src:dst';
my %sse_mnemonic = map { (split /:/)[0] => 1 } keys %sse;
my %flag = map { $_ => 1 } qw(ac af cf df if of pf rflags sf zf);
my %effect = (%flag, map { $_ => 1 } qw(ax eax ebx ecx edx rax rbp rcx rdx r11 rip rsp
    dst src dst.address src.address memory memory.stack system.unknown x87.state));
my %feature = map { $_ => 1 } qw(base cpuid msr rdtscp smap sse sse2 syscall tsc x87 xsave);
my %flag_action;
for my $f (keys %flag) {
    $flag_action{"$f:$_"} = 1 for qw(write zero one undefined unknown);
}
my $source = read_bytes($schema);
refuse('only printable ASCII, TAB and LF are allowed; pipes are forbidden')
    if $source =~ /[^\x09\x0a\x20-\x7e]|\|/;
refuse('final LF is required') unless $source =~ /\n\z/;
my @lines = split /\n/, $source, -1;
pop @lines;
refuse('expected 1..1024 forms') unless @lines >= 2 && @lines <= 1025;
refuse('incorrect TSV header or column order') unless shift(@lines) eq join("\t", @columns);
my (@rows, %ids, %forms);
my ($previous_mnemonic, $previous_width, $previous_encoding) = ('', -1, '');
$line_no = 1;
for my $line (@lines) {
    ++$line_no;
    refuse('line exceeds 1024 bytes') if length($line) > 1024;
    my @fields = split /\t/, $line, -1;
    refuse('expected exactly 12 fields') unless @fields == @columns;
    refuse('fields must contain 1..192 bytes') if grep { !length($_) || length($_) > 192 } @fields;
    my %r;
    @r{@columns} = @fields;
    refuse('invalid lowercase id') unless $r{id} =~ /\A[a-z][a-z0-9_]{0,63}\z/;
    refuse('duplicate id') if $ids{$r{id}}++;
    refuse('unknown mnemonic') unless $fixed{$r{mnemonic}} || $rr{$r{mnemonic}} || $rotate{$r{mnemonic}} || $sse_mnemonic{$r{mnemonic}};
    refuse('mode must be 64') unless $r{mode} eq '64';
    refuse('invalid encoding') unless $r{encoding} =~ /\A(?:fixed|gpr_rr|gpr_rotate|sse_rr|sse_rm|sse_mr|sse_xg|sse_gx|sse_shift|sse_shuf)\z/;
    refuse('invalid width') unless $r{width} =~ /\A(?:0|8|16|32|64|128)\z/;
    refuse('opcode must be 1..4 lowercase hex bytes separated by single spaces')
        unless $r{opcode} =~ /\A[0-9a-f]{2}(?: [0-9a-f]{2}){0,3}\z/;
    if ($r{encoding} eq 'fixed') {
        refuse('invalid fixed form') unless $fixed{$r{mnemonic}} && $r{width} eq '0'
            && $r{operands} eq 'none';
    } elsif ($r{encoding} eq 'gpr_rr') {
        refuse('invalid gpr_rr form') unless $rr{$r{mnemonic}} && $r{width} =~ /\A(?:8|16|32|64)\z/
            && $r{operands} eq 'gpr,gpr' && length($r{opcode}) == 2;
        refuse('adc supports only RR32/64 opcode 11') if $r{mnemonic} eq 'adc'
            && ($r{width} !~ /\A(?:32|64)\z/ || $r{opcode} ne '11');
    } elsif ($r{encoding} eq 'gpr_rotate') {
        refuse('invalid bounded gpr_rotate form') unless $rotate{$r{mnemonic}}
             && "$r{width}:$r{operands}:$r{opcode}" eq $rotate{$r{mnemonic}};
    } else {
        my $expected = $sse{"$r{mnemonic}:$r{encoding}"};
        refuse('invalid bounded SSE form/effects') unless defined $expected &&
            "$r{width}:$r{operands}:$r{opcode}:$r{reads}:$r{writes}" eq $expected &&
            $r{flags} eq 'none' && $r{control} eq 'next' &&
            $r{features} eq ($r{mnemonic} =~ /\Amov[au]ps\z/ ? 'sse' : 'sse2');
    }
    refuse('duplicate form') if $forms{"$r{mnemonic}:$r{width}:$r{encoding}"}++;
    refuse('forms must be sorted by mnemonic then numeric width')
        unless $r{mnemonic} gt $previous_mnemonic ||
            ($r{mnemonic} eq $previous_mnemonic && ($r{width} > $previous_width ||
             ($r{width} == $previous_width && $r{encoding} gt $previous_encoding)));
    ($previous_mnemonic, $previous_width, $previous_encoding) = @r{qw(mnemonic width encoding)};
    my @reads = token_list($r{reads}, \%effect, 'reads');
    my @writes = token_list($r{writes}, \%effect, 'writes');
    refuse('fixed form cannot use operand placeholders')
        if $r{encoding} eq 'fixed' && grep { $_ eq 'dst' || $_ eq 'src' } (@reads, @writes);
    my @features = token_list($r{features}, \%feature, 'features');
    refuse('features must be nonempty; base must stand alone')
        unless @features && !(@features > 1 && $features[0] eq 'base');
    my @flags = token_list($r{flags}, \%flag_action, 'flags');
    my %declared;
    for my $entry (@flags) {
        my ($name, $action) = split /:/, $entry;
        refuse('duplicate flag') if $declared{$name}++;
        refuse('aggregate rflags must be unknown') if $name eq 'rflags' && $action ne 'unknown';
    }
    refuse('aggregate and individual flags cannot be mixed') if $declared{rflags} && @flags != 1;
    refuse('flags must match the flag intersection of writes')
        unless join(',', sort keys %declared) eq join(',', grep { $flag{$_} } @writes);
    refuse('invalid control') unless $r{control} =~ /\A(?:next|return|system|halt|trap|barrier)\z/;
    refuse('GPR form requires base features and next control')
        if $r{encoding} =~ /^gpr_/ && ($r{features} ne 'base' || $r{control} ne 'next');
    push @rows, \%r;
}
$line_no = 0;
my $count = scalar @rows;
my $digest = sha256_hex($source);
# REUSE-IgnoreStart
my $header = <<'HEADER';
/* Generated by isa/generate.pl; do not edit. INV-594.
 * Mode 64 only. Effects are declared metadata, not a semantic proof.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BASM_INTENT_FORMS_H
#define BASM_INTENT_FORMS_H

#define INTENT_FIXED 0
#define INTENT_GPR_RR 1
#define INTENT_GPR_ROTATE 2
#define INTENT_SSE_RR 3
#define INTENT_SSE_RM 4
#define INTENT_SSE_MR 5
#define INTENT_SSE_XG 6
#define INTENT_SSE_GX 7
#define INTENT_SSE_SHIFT 8
#define INTENT_SSE_SHUF 9

typedef struct IntentForm {
    const char *id;
    const char *mnemonic;
    const char *operands;
    const char *reads;
    const char *writes;
    const char *flags;
    const char *features;
    const char *control;
    unsigned char opcode[4];
    int opcode_len;
    int width;
    int encoding;
} IntentForm;

HEADER
# REUSE-IgnoreEnd
$header .= "/* forms.tsv SHA-256: $digest */\nstatic const IntentForm g_intent_forms[] = {\n";
for my $r (@rows) {
    my @bytes = map { "0x$_" } split / /, $r->{opcode};
    my $len = scalar @bytes;
    push @bytes, '0x00' while @bytes < 4;
    $header .= '    { ' . join(', ', map { qq("$r->{$_}") } @columns[0..7]) . ', { '
        . join(', ', @bytes) . " }, $len, $r->{width}, "
        . 'INTENT_' . uc($r->{encoding}) . " },\n";
}
$header .= "};\n\n#define INTENT_FORM_COUNT $count\n\n";
my %registered_sse;
# INV-782: movsd stays out of the registered names — the legacy string-op
# dispatch owns the mnemonic and routes operand forms to enc_sse itself.
my @sse_names = map { $_->{mnemonic} }
    grep { $_->{encoding} =~ /^sse_/ && $_->{mnemonic} ne 'movsd' && !$registered_sse{$_->{mnemonic}}++ } @rows;
$header .= "/* INV-740: registration shares the closed schema vocabulary. */\n#define INTENT_SSE_NAMES(kind) "
    . join(', ', map { qq({ "$_", kind }) } @sse_names) . "\n\n#endif\n";
my $fixed_count = grep { $_->{encoding} eq 'fixed' } @rows;
my $rr_count = grep { $_->{encoding} eq 'gpr_rr' } @rows;
my $rotate_count = grep { $_->{encoding} eq 'gpr_rotate' } @rows;
my $sse_count = grep { $_->{encoding} =~ /^sse_/ } @rows;
# REUSE-IgnoreStart
my $inventory = "# IC03 Form Inventory\n\n"
    . "<!--\nAuthor: F E R M I ∞ H A R T <contact\@fermihart.com>\n"
    . "SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact\@fermihart.com>\n"
    . "SPDX-License-Identifier: BSD-3-Clause\n-->\n\n"
    . "Generated by `isa/generate.pl`; do not edit. INV-594.\n\n"
    . "Schema SHA-256: `$digest`.\n\n"
    . "$count forms: $fixed_count fixed, $rr_count GPR register-register, $rotate_count bounded GPR rotate, $sse_count bounded SSE. Mode 64 only.\n\n"
    . "Declared metadata, not verified semantics or a memory-safety proof. `system.unknown`\n"
    . "is deliberately opaque. See [README.md](README.md) for field definitions and limits.\n\n"
    . '| ' . join(' | ', @columns) . " |\n| " . join(' | ', ('---') x @columns) . " |\n";
# REUSE-IgnoreEnd
for my $r (@rows) {
    $inventory .= '| ' . join(' | ', map { $r->{$_} } @columns) . " |\n";
}
if ($check) {
    refuse('stale intent_forms.h; regenerate') unless read_bytes("$Bin/intent_forms.h") eq $header;
    refuse('stale INVENTORY.md; regenerate') unless read_bytes("$Bin/INVENTORY.md") eq $inventory;
    print "ISA schema: $count forms; header and inventory fresh\n";
} elsif (defined $output) {
    open my $fh, '>:raw', $output or refuse('cannot open output');
    print {$fh} ($format eq 'header' ? $header : $inventory) or refuse('output write failed');
    close $fh or refuse('output close failed');
} else {
    binmode STDOUT, ':raw';
    print ($format eq 'header' ? $header : $inventory) or refuse('stdout write failed');
    close STDOUT or refuse('stdout close failed');
}
