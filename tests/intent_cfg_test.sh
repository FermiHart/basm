#!/bin/sh
# INV-596: inspect instruction-span edges, never execute the emitted code.
# CLI uses an existing product; optional host unit/syntax checks use only temp
# files. No shared build or global gate.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
exec perl - "${BASM:-$ROOT/basm}" "$ROOT" <<'PERL'
use strict;
use warnings;
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
my ($basm, $root) = @ARGV;
my $tmp = tempdir('basm-cfg-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my $checks = 0;
sub check { my ($ok, $why) = @_; die "FAIL cfg: $why\n" unless $ok; $checks++ }
sub put { open my $f, '>:raw', $_[0] or die $!; print {$f} $_[1]; close $f or die $! }
sub get { open my $f, '<:raw', $_[0] or die $!; local $/; return scalar(<$f>) // '' }
sub explain {
    put("$tmp/source.basm", "bits 64\nsection .text\n" . $_[0]);
    for my $mode ('plain', 'explain') {
        my $pid = fork(); defined $pid or die $!;
        if (!$pid) {
            open STDOUT, '>:raw', "$tmp/$mode.json" or die $!;
            open STDERR, '>:raw', "$tmp/$mode.err" or die $!;
            my @opts = $mode eq 'explain' ? ('--explain') : ();
            exec {$basm} $basm, '--target-profile', 'public', @opts,
                '-f', 'elf64', '-o', "$tmp/$mode.o", "$tmp/source.basm";
            die "exec: $!";
        }
        waitpid($pid, 0);
        check($? == 0, "$mode assembly: " . get("$tmp/$mode.err"));
    }
    check(get("$tmp/plain.o") eq get("$tmp/explain.o"), 'CFG does not change the object');
    my $v = decode_json(get("$tmp/explain.json"));
    my $c = $v->{cfg};
    check(ref($c) eq 'HASH' && $c->{status} eq 'partial' && !$c->{complete}, 'explicitly incomplete partial CFG');
    check($v->{semantic_verification} eq 'unimplemented' && $c->{scope} eq 'instruction-spans',
          'byte evidence, not semantic or artifact-hash proof');
    check($c->{node_count} == @{$v->{records}}, 'one-based nodes correspond to record order');
    for my $e (@{$c->{edges}}) {
        check($e->{from} >= 1 && $e->{from} <= $c->{node_count}, 'valid source node');
        if (defined $e->{to}) {
            check($e->{to} >= 1 && $e->{to} <= $c->{node_count} && !defined($e->{reason}), 'resolved edge');
            my $dst = $v->{records}[$e->{to}-1];
            check($dst->{section} == $e->{target_section} && $dst->{offset} == $e->{target_offset} &&
                  $dst->{section} == $v->{records}[$e->{from}-1]{section}, 'exact same-section instruction start');
        } else {
            check(defined $e->{reason}, 'unresolved edge has a reason');
        }
    }
    for my $b (@{$c->{boundaries}}) {
        check($b->{node} >= 1 && $b->{node} <= $c->{node_count}, 'valid boundary node');
        check(!scalar(grep { $_->{from} == $b->{node} } @{$c->{edges}}), 'boundary does not infer successors');
    }
    return $v;
}
sub edge {
    my ($v, $from, $kind, $to, $reason) = @_;
    my @e = grep { $_->{from} == $from && $_->{kind} eq $kind } @{$v->{cfg}{edges}};
    check(@e == 1, "one $kind edge from node $from");
    check(defined($to) ? defined($e[0]{to}) && $e[0]{to} == $to : !defined($e[0]{to}), "destination of $kind from $from");
    check(defined($reason) ? defined($e[0]{reason}) && $e[0]{reason} eq $reason : !defined($e[0]{reason}), "reason of $kind from $from");
    if (defined($reason) && $reason eq 'relocation') {
        check(!defined($e[0]{target_section}) && !defined($e[0]{target_offset}), 'relocation bytes are not final addresses');
    }
}
sub boundary {
    my ($v, $node, $kind, $terminal) = @_;
    my @b = grep { $_->{node} == $node } @{$v->{cfg}{boundaries}};
    check(@b == 1 && $b[0]{kind} eq $kind && !!$b[0]{terminal} == !!$terminal, "node $node is $kind boundary");
}

if ($ENV{INTENT_CFG_UNIT_ONLY} || $ENV{INTENT_CFG_SYNTAX_ONLY}) {
    # Legal assembly cannot put a label inside a single recorded instruction.
    # Supply raw spans directly to test such targets and rel32 arithmetic.
    put("$tmp/unit.c", <<'C');
#include "modules/01_foundation.inc"
#include <assert.h>
static void data_define(int unit, int ntok) { (void)unit; (void)ntok; abort(); }
static void qualify(const char *target, char *out) { (void)target; (void)out; abort(); }
static void span(const char *bytes, int size, const IntentForm *form) {
    int start = cur_off();
    emit_span((const uint8_t *)bytes, (size_t)size);
    intent_trace_record(g_cur, start, cur_off(), 1, form);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "off")) { intent_cfg_write(stdout); return 0; }
    g_explain = 1;
    int file = intent_file_intern("raw-fixture");
    intent_location_origin(intent_origin_add(file, 1, 0, 0));
    intent_expanded_newline();
    if (!strcmp(argv[1], "limit")) {
        const IntentForm *nop = NULL;
        for (int i = 0; i < INTENT_FORM_COUNT; i++)
            if (!strcmp(g_intent_forms[i].id, "nop")) nop = &g_intent_forms[i];
        assert(nop);
        for (int i = 0; i < INTENT_TRACE_MAX; i++) {
            g_cur = i & 1 ? SEC_DATA : SEC_TEXT;
            span("\x90", 1, nop);
        }
        add_reloc_named(cur_off()-4, "external", 0);
        intent_cfg_write(stdout);
        intent_trace_free(); free(g_text); free(g_data); return 0;
    }
    span("\xeb\xff", 2, NULL);                   /* node 1: middle of self */
    span("\xe9\xff\xff\xff\x7f", 5, NULL);      /* node 2: above INT_MAX */
    span("\xe9\x00\x00\x00\x80", 5, NULL);      /* node 3: negative target */
    span("\xeb\xfe", 2, NULL);                   /* node 4: direct self-loop */
    span("\xe9", 1, NULL);                        /* node 5: truncated */
    span("\xeb\xfe\x00", 3, NULL);              /* node 6: overlong */
    span("\x48\x8d\x03", 3, NULL);              /* node 7: unknown LEA */
    g_cur = SEC_DATA;
    span("\xe8\x00\x00\x00\x00", 5, NULL);   /* node 8: external call */
    span("\xc3", 1, NULL);                        /* node 9: unmodeled */
    add_reloc_named(1, "external", -4);
    if (!strcmp(argv[1], "count")) g_intent_nrecords = INTENT_TRACE_MAX + 1;
    if (!strcmp(argv[1], "section")) g_intent_records[0].section = SEC_MAX;
    if (!strcmp(argv[1], "overlap")) g_intent_records[1].offset = 1;
    if (!strcmp(argv[1], "relocation")) g_relocs[0].section = SEC_MAX;
    intent_cfg_write(stdout);
    intent_trace_free(); free(g_text); free(g_data);
    return 0;
}
C
    my @opts = $ENV{INTENT_CFG_SYNTAX_ONLY} ? ('-fsyntax-only') : ('-o', "$tmp/unit");
    my @flags = split /\s+/, ($ENV{INTENT_CFG_CFLAGS} // '');
    system($ENV{CC} // 'cc', '-std=c99', '-O1', @flags, '-I', $root, @opts, "$tmp/unit.c") == 0
        or die "CFG host compile failed\n";
    if ($ENV{INTENT_CFG_SYNTAX_ONLY}) { print "PASS CFG host syntax only; behavior not tested\n"; exit 0; }
    for my $mode (qw(raw limit off count section overlap relocation)) {
        my $pid = fork(); defined $pid or die $!;
        if (!$pid) {
            open STDOUT, '>:raw', "$tmp/unit.json" or die $!;
            open STDERR, '>:raw', "$tmp/unit.err" or die $!;
            exec "$tmp/unit", $mode; die $!;
        }
        waitpid($pid, 0);
        my $rc = $?;
        if ($mode eq 'raw') {
            check($rc == 0, 'raw unit completed');
            my $v = { cfg => decode_json(get("$tmp/unit.json")) };
            check($v->{cfg}{node_count} == 9 && !$v->{cfg}{complete}, 'raw graph remains incomplete');
            edge($v, 1, 'jump', undef, 'not-instruction-start');
            edge($v, 2, 'jump', undef, 'not-instruction-start');
            edge($v, 3, 'jump', undef, 'not-instruction-start');
            check($v->{cfg}{edges}[1]{target_offset} == 2147483654 &&
                  $v->{cfg}{edges}[2]{target_offset} == -2147483636, 'signed rel32 targets do not wrap');
            edge($v, 4, 'jump', 4);
            boundary($v, 5, 'unknown-control', 0);
            boundary($v, 6, 'unknown-control', 0);
            boundary($v, 7, 'unknown-control', 0);
            edge($v, 8, 'call', undef, 'relocation');
            edge($v, 8, 'call-continuation', 9);
            boundary($v, 9, 'unknown-control', 0);
        } elsif ($mode eq 'limit') {
            check($rc == 0, '65536-record interleaved-section index');
            my $v = { cfg => decode_json(get("$tmp/unit.json")) };
            check($v->{cfg}{node_count} == 65536 && @{$v->{cfg}{edges}} == 65532 &&
                  @{$v->{cfg}{boundaries}} == 4, 'maximum index and relocation overlaps reconcile');
            edge($v, 1, 'fallthrough', 3);
            boundary($v, 65536, 'relocation', 0);
        } elsif ($mode eq 'off') {
            check($rc == 0 && get("$tmp/unit.json") eq '', 'no CFG side effects without explain');
        } else {
            check($rc == 256 && get("$tmp/unit.json") eq '' && get("$tmp/unit.err") =~ /intent cfg/,
                  "bounded unit refusal: $mode");
        }
    }
    print "PASS CFG host unit: $checks checks; product not rebuilt\n";
    exit 0;
}

my $v = explain("extern extfn\ncmp eax, ebx\nje short taken\ndb 204\ntaken:\nnop\nself:\njmp short self\ncall extfn\nlea rax, [rbx]\njmp rax\nret\nsyscall\nud2\nhlt\n");
check(@{$v->{records}} == 11, 'fixture record count excludes data and labels');
edge($v, 1, 'fallthrough', 2);
edge($v, 2, 'branch', 3);
edge($v, 2, 'fallthrough', undef, 'not-instruction-start');
edge($v, 3, 'fallthrough', 4);
edge($v, 4, 'jump', 4);
edge($v, 5, 'call', undef, 'relocation');
edge($v, 5, 'call-continuation', 6);
boundary($v, 6, 'unknown-control', 0);
boundary($v, 7, 'unknown-control', 0);
boundary($v, 8, 'return', 1);
boundary($v, 9, 'system', 0);
boundary($v, 10, 'trap', 1);
boundary($v, 11, 'halt', 1);

$v = explain("nop\nsection .data\nret\nsection .text\nlfence\nret\nsection .more\nnop\ndb 0\nret\n");
edge($v, 1, 'fallthrough', 3);
edge($v, 3, 'fallthrough', 4);
edge($v, 5, 'fallthrough', undef, 'not-instruction-start');
boundary($v, 2, 'return', 1);

$v = explain("call worker\nret\nsection .worker\nworker:\nret\n");
edge($v, 1, 'call', undef, 'relocation');
edge($v, 1, 'call-continuation', 2);
$v = explain("call worker\nnop\nworker:\nret\n");
edge($v, 1, 'call', 3);
edge($v, 1, 'call-continuation', 2);

$v = explain("jmp near nearself\nnearself:\njmp near nearself\nloopself:\nloop loopself\nret\n");
check($v->{records}[0]{bytes} =~ /^e9/ && $v->{records}[1]{bytes} eq 'e9fbffffff', 'near jump encodings');
edge($v, 1, 'jump', 2);
edge($v, 2, 'jump', 2);
edge($v, 3, 'branch', 3);
edge($v, 3, 'fallthrough', 4);

my @cc = qw(jb jae je jne jbe ja js jns jl jge jle jg);
my $source = '';
for my $i (0 .. $#cc) {
    $source .= "short$i:\n$cc[$i] short short$i\nnear$i:\n$cc[$i] near near$i\n";
}
$v = explain($source . "ret\n");
for my $i (1 .. 2*@cc) {
    check($v->{records}[$i-1]{size} == ($i % 2 ? 2 : 6), 'exact short/near Jcc span');
    edge($v, $i, 'branch', $i);
    edge($v, $i, 'fallthrough', $i+1);
}

# A data label is not a node even when its bytes decode as an instruction.
$v = explain("jmp short gap\ngap:\ndb 144\nret\n");
edge($v, 1, 'jump', undef, 'not-instruction-start');
$v = explain("rep jmp near finish\nfinish:\nret\n");
boundary($v, 1, 'unknown-control', 0);
$v = explain("nop\n");
edge($v, 1, 'fallthrough', undef, 'not-instruction-start');
$v = explain('');
check($v->{cfg}{node_count} == 0 && !@{$v->{cfg}{edges}} && !@{$v->{cfg}{boundaries}}, 'empty graph stays incomplete');

print "PASS intent CFG: $checks structural checks; no semantic/reachability proof\n";
PERL
