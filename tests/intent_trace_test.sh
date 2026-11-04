#!/bin/sh
# INV-596: explanation describes emitted bytes and provenance, not a proof.
# CLI mode uses an existing binary; INTENT_UNIT_ONLY compiles a temp harness.
# Neither mode builds shared targets or runs the global gate.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
exec perl - "${BASM:-$ROOT/basm}" "$ROOT" <<'PERL'
use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use JSON::PP qw(decode_json);
my $basm = shift;
my $root = shift;
my $tmp = tempdir('basm-intent-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my $checks = 0;
sub check { my ($ok, $why) = @_; die "FAIL intent: $why\n" unless $ok; $checks++ }
sub put { my ($p, $s) = @_; open my $f, '>:raw', $p or die "$p: $!"; print {$f} $s; close $f or die $! }
sub get { open my $f, '<:raw', $_[0] or die "$_[0]: $!"; local $/; return scalar(<$f>) // '' }
sub run {
    my (@args) = @_;
    my $pid = fork(); defined $pid or die $!;
    if (!$pid) {
        open STDOUT, '>:raw', "$tmp/stdout" or die $!;
        open STDERR, '>:raw', "$tmp/stderr" or die $!;
        exec {$basm} $basm, @args;
        die "exec $basm: $!";
    }
    waitpid($pid, 0);
    return ($?, get("$tmp/stdout"), get("$tmp/stderr"));
}

# Optional isolated helper verification while main's integration is pending.
# No shared binary, object, Makefile target or global gate is touched.
if ($ENV{INTENT_UNIT_ONLY}) {
    put("$tmp/unit.c", <<'C');
#include "modules/01_foundation.inc"
#ifndef BASM_INTENT_FORMS_H
static int g_explain, g_json_diagnostics;
static char g_last_open_path[1024];
#include "isa/intent_forms.h"
#include "intent/trace.inc"
#endif
#include "modules/05_preprocessor.inc"
#include <assert.h>
static void data_define(int unit, int ntok) { (void)unit; (void)ntok; abort(); }
static void qualify(const char *target, char *out) { (void)target; (void)out; abort(); }
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *mode = argv[1];
    g_srcname = "source\"\\\t.basm";
    if (!strcmp(mode, "off")) {
        intent_file_intern(NULL); intent_origin_add(-1, -1, -1, -1);
        intent_expanded_newline(); intent_trace_record(-1, -1, -1, -1, NULL);
        intent_trace_reset_pass(); intent_trace_write(stdout);
        assert(!g_intent_files && !g_intent_origins && !g_intent_records && !g_intent_expanded);
        char *src = strdup("nop\n");
        assert(preprocess(src, 4) == src);
        free(src); intent_trace_free(); return 0;
    }
    g_explain = 1; g_target_profile = 2;
    if (!strcmp(mode, "nested")) {
        const char *text = "%macro INNER 0\nnop\n%endmacro\n%macro OUTER 0\nINNER\n%endmacro\n%if 0\nignored\n%endif\n%rep 2\nOUTER\n%endrep\nret\n";
        char *src = preprocess(strdup(text), (long)strlen(text));
        assert(!strcmp(src, "nop\nnop\nret\n"));
        assert(g_intent_nexpanded == 3);
        for (int line = 1; line <= 2; line++) {
            IntentOrigin *o = &g_intent_origins[intent_expanded_origin(line)-1];
            assert(o->line == 2 && g_intent_origins[o->definition-1].line == 1);
            o = &g_intent_origins[o->parent-1]; assert(o->line == 5);
            o = &g_intent_origins[o->parent-1]; assert(o->line == 11);
            o = &g_intent_origins[o->parent-1]; assert(o->line == 10);
        }
        assert(g_intent_origins[intent_expanded_origin(3)-1].line == 13);
        free(src); intent_trace_free(); return 0;
    }
    if (!strcmp(mode, "skipped-error")) {
        const char *text = "%macro M 0\nnop\n%endmacro\n%rep 0\nnop\n%endrep\n%endif\n";
        /* Exercise diagnostic state even before foundation's die is wired. */
        PPContext ctx; memset(&ctx, 0, sizeof(ctx));
        const char *cursor = text; int line = 1;
        int file = intent_file_intern(g_srcname);
        pp_trace_raw(&cursor, &line, strstr(text, "%endif"), file, 0);
        intent_diagnostic("unexpected \"endif\"\n", "detail\\\t");
        intent_trace_free(); return 0;
    }
    int file = intent_file_intern(g_srcname);
    int origin = intent_origin_add(file, 7, 0, 0);
    intent_location_origin(origin); intent_expanded_newline();
    const IntentForm *nop = NULL;
    for (int i = 0; i < INTENT_FORM_COUNT; i++)
        if (!strcmp(g_intent_forms[i].id, "nop")) nop = &g_intent_forms[i];
    assert(nop);
    g_cur = SEC_TEXT; emit(0x90);
    if (!strcmp(mode, "origin-limit"))
        for (int i = 0; i < INTENT_TRACE_MAX; i++) intent_origin_add(file, 8, origin, 0);
    if (!strcmp(mode, "map-limit"))
        for (int i = 0; i < INTENT_TRACE_MAX; i++) intent_expanded_newline();
    if (!strcmp(mode, "record-limit"))
        for (int i = 0; i <= INTENT_TRACE_MAX; i++) intent_trace_record(SEC_TEXT, 0, 1, 1, nop);
    if (!strcmp(mode, "file-limit"))
        for (int i = 0; i < INTENT_FILE_MAX; i++) {
            char path[32]; snprintf(path, sizeof(path), "file-%d", i); intent_file_intern(path);
        }
    if (!strcmp(mode, "path-limit")) {
        char path[1025]; memset(path, 'x', 1024); path[1024] = 0; intent_file_intern(path);
    }
    if (!strcmp(mode, "bad-span")) intent_trace_record(SEC_TEXT, 0, 2, 1, NULL);
    if (!strcmp(mode, "bad-section")) intent_trace_record(SEC_CUSTOM0 + CUSTOM_MAX, 0, 1, 1, NULL);
    if (!strcmp(mode, "span-limit")) intent_trace_record(SEC_TEXT, 0, 257, 1, NULL);
    if (!strcmp(mode, "modeled-long")) intent_trace_record(SEC_TEXT, 0, 16, 1, nop);
    if (!strcmp(mode, "span256")) {
        emit_fill(0x66, 255); intent_trace_record(SEC_TEXT, 0, 256, 1, NULL);
        intent_trace_write(stdout);
    } else {
        intent_trace_record(SEC_TEXT, 0, 1, 1, nop);
        intent_trace_reset_pass();
        assert(g_intent_nrecords == 0 && intent_expanded_origin(1) == origin);
        intent_trace_record(SEC_TEXT, 0, 1, 1, nop);
        emit(1); intent_trace_record(SEC_TEXT, 1, 2, 1, NULL); g_text[1] = 2;
        intent_trace_write(stdout);
    }
    intent_trace_free();
    assert(!g_intent_files && !g_intent_origins && !g_intent_records && !g_intent_expanded);
    assert(!g_intent_norigins && !g_intent_nrecords && !g_intent_nexpanded);
    free(g_text);
    return 0;
}
C
    my @flags = split /\s+/, ($ENV{INTENT_UNIT_CFLAGS} // '');
    system($ENV{CC} // 'cc', '-std=c99', '-O1', @flags, '-I', $root,
           "$tmp/unit.c", '-o', "$tmp/unit") == 0 or die "unit compile failed\n";
    $basm = "$tmp/unit";
    for my $mode ('off', 'nested') {
        my ($rc, $out, $err) = run($mode);
        check($rc == 0 && $out eq '', "isolated $mode: $err");
    }
    my ($rc, $out, $err) = run('trace');
    check($rc == 0, "isolated trace: $err");
    my $v = decode_json($out);
    check(@{$v->{records}} == 2 && $v->{records}[1]{bytes} eq '02' &&
          $v->{coverage}{modeled} == 1 && $v->{coverage}{unmodeled} == 1,
          'pass reset retains provenance and byte reads use final buffers');
    ($rc, $out, $err) = run('span256');
    check($rc == 0 && decode_json($out)->{records}[0]{size} == 256, 'unmodeled 256-byte prefix span');
    ($rc, $out, $err) = run('skipped-error');
    my $d = decode_json($err);
    check($rc == 0 && $d->{line} == 7 && $d->{file} eq "source\"\\\t.basm" &&
          $d->{message} eq "unexpected \"endif\"\n" && $d->{detail} eq "detail\\\t",
          'raw cursor and diagnostic JSON escaping');
    for my $mode (qw(origin-limit map-limit record-limit file-limit path-limit bad-span bad-section span-limit modeled-long)) {
        ($rc, $out, $err) = run($mode);
        check($rc == 256 && $out eq '' && $err =~ /intent/, "isolated rejection $mode: $err");
    }
    print "PASS intent helpers: $checks isolated checks; CLI integration not tested\n";
    exit 0;
}

sub assemble {
    my ($src, @opts) = @_;
    my ($rc, $out, $err) = run('--target-profile', 'public', @opts,
        '-f', 'elf64', '-o', "$tmp/out.o", $src);
    check($rc == 0, "assemble @opts: $err");
    return ($out, get("$tmp/out.o"));
}
sub explained {
    my ($src, @opts) = @_;
    my (undef, $plain) = assemble($src, @opts);
    my ($json, $object) = assemble($src, '--explain', @opts);
    check($plain eq $object, 'explain leaves object byte-identical');
    my $v = decode_json($json);
    check($v->{profile} eq 'public', 'selected profile');
    check($v->{semantic_verification} eq 'unimplemented', 'no semantic proof claim');
    check(ref($v->{cfg}) eq 'HASH' && $v->{cfg}{status} eq 'partial' &&
          !$v->{cfg}{complete} && $v->{cfg}{node_count} == @{$v->{records}}, 'partial CFG is not a proof');
    my %origin = map { $_->{id} => $_ } @{$v->{origins}};
    for my $o (@{$v->{origins}}) {
        check($o->{line} > 0 && defined $o->{file}, 'source location exists');
        check(!defined($o->{parent}) || (exists($origin{$o->{parent}}) && $o->{parent} < $o->{id}),
              'bounded acyclic expansion parent');
        check(!defined($o->{definition}) || (exists($origin{$o->{definition}}) && $o->{definition} < $o->{id}),
              'bounded macro definition reference');
    }
    # Read the object's ELF64 section headers independently of the trace.
    my $shoff = unpack('Q<', substr($object, 40, 8));
    my ($shsize, $shnum, $stridx) = unpack('v3', substr($object, 58, 6));
    my ($stroff, $strlen) = unpack('Q<2', substr($object, $shoff + $stridx * $shsize + 24, 16));
    my $strings = substr($object, $stroff, $strlen);
    my %section;
    for my $i (0 .. $shnum - 1) {
        my $h = substr($object, $shoff + $i * $shsize, $shsize);
        my $nameoff = unpack('V', $h);
        my ($off, $size) = unpack('Q<2', substr($h, 24, 16));
        my ($name) = substr($strings, $nameoff) =~ /^([^\0]*)/;
        $section{$name} = substr($object, $off, $size);
    }
    my ($modeled, $unmodeled) = (0, 0);
    for my $r (@{$v->{records}}) {
        check(exists $origin{$r->{origin}}, 'instruction has an origin');
        check($r->{expanded_line} > 0 && $r->{offset} >= 0 && $r->{size} > 0 && $r->{size} <= 256,
              'bounded instruction coordinates');
        check($r->{bytes} eq unpack('H*', substr($section{$r->{section_name}}, $r->{offset}, $r->{size})),
              'trace bytes equal object section span');
        if (defined $r->{form}) {
            $modeled++;
            check($r->{status} eq 'modeled' && $r->{size} <= 15 && ref($r->{effects}) eq 'HASH',
                  'modeled form has bounded bytes and declared effects');
        } else {
            $unmodeled++;
            check($r->{status} eq 'unmodeled' && !defined($r->{effects}) && $r->{control} eq 'unknown',
                  'unmodeled form does not fabricate effects/control');
        }
    }
    check($v->{coverage}{instructions} == @{$v->{records}} &&
          $v->{coverage}{modeled} == $modeled && $v->{coverage}{unmodeled} == $unmodeled &&
          $v->{coverage}{schema_forms} == 109, 'coverage reconciles');
    return ($v, \%origin);
}

my $raw = "$tmp/raw.basm";
put($raw, "bad equ 1 << 64\nnop\n");
my ($equ_rc, undef, $equ_err)=run('--target-profile','public','--diagnostics-json',
    '-f','elf64','-o',"$tmp/equ-error.o",$raw);
check($equ_rc==256 && decode_json($equ_err)->{line}==1,
      'EQU prescan error belongs to its expanded source line');
put($raw, "bits 64\nsection .text\nglobal entry\nentry:\nmov rax, rbx\nxor eax, eax\nlea rdx, [rax+8]\njmp .done\ndb 127\n.done:\nret\nsection .data\nret\ndb 7\nsection .rodata\nnop\nsection .trace_code\nnop\n");
my ($v, $o) = explained($raw);
check(@{$v->{records}} == 8, 'labels/data/directives are not instructions; all sections covered');
check($v->{coverage}{unmodeled} == 2, 'lea and branch remain unmodeled');
my @r = @{$v->{records}};
check($r[0]{form} eq 'mov_rr64' && $r[0]{offset} == 0 && $r[0]{bytes} eq '4889d8', 'labeled mov byte span');
check($r[1]{effects}{flags} =~ /af:undefined/ && $r[1]{effects}{writes} =~ /dst/, 'schema effects preserved');
check($r[4]{form} eq 'ret' && $r[4]{offset} == 12 && $r[4]{control} eq 'return', 'branch relaxation and data gap');
check($r[4]{effects}{reads} =~ /system\.unknown/, 'unknown schema effects not erased');
check($o->{$r[4]{origin}}{line} == 11, 'raw no-PP source line');

my $incdir = "$tmp/include-path";
make_path($incdir);
put("$incdir/leaf.inc", "%macro INNER 0\nmov rax, rbx\n%endmacro\nnop\n");
put("$incdir/outer.inc", "%include \"leaf.inc\"\n%macro OUTER 0\nINNER\n%endmacro\n");
my $source = "$tmp/expanded.basm";
put($source, "bits 64\n%include \"outer.inc\"\n%if 0\nignored\n%endif\n%rep 2\nOUTER\n%endrep\nret\n");
($v, $o) = explained($source, '-I', $incdir);
@r = @{$v->{records}};
check(@r == 4, 'include plus nested macro in repetition');
my $leaf = $o->{$r[0]{origin}};
check($leaf->{file} eq "$incdir/leaf.inc" && $leaf->{line} == 4, 'resolved included path and raw line');
my $parent = $o->{$leaf->{parent}};
check($parent->{file} eq "$incdir/outer.inc" && $parent->{line} == 1 &&
      $o->{$parent->{parent}}{file} eq $source && $o->{$parent->{parent}}{line} == 2, 'nested include parents');
for my $i (1, 2) {
    my $loc = $o->{$r[$i]{origin}};
    check($loc->{file} eq "$incdir/leaf.inc" && $loc->{line} == 2, 'macro definition line plus offset');
    check($o->{$loc->{definition}}{line} == 1, 'macro definition origin reference');
    my $call = $o->{$loc->{parent}};
    check($call->{file} eq "$incdir/outer.inc" && $call->{line} == 3, 'nested macro caller');
    my $rep = $o->{$call->{parent}};
    check($rep->{file} eq $source && $rep->{line} == 7 && $o->{$rep->{parent}}{line} == 6,
          'repeated body keeps original line and repetition caller');
}
check($r[1]{origin} != $r[2]{origin}, 'repeated invocation has a distinct expansion origin');
check($o->{$r[3]{origin}}{line} == 9, 'raw newline cursor includes skipped macro/rep bodies');

put("$tmp/source-dir.inc", "ret");
put($source, "%include \"source-dir.inc\"\n");
($v, $o) = explained($source);
check($o->{$v->{records}[0]{origin}}{file} eq "$tmp/source-dir.inc" &&
      $o->{$v->{records}[0]{origin}}{line} == 1, 'source-directory include resolution and unterminated final line');

my $escape = "$tmp/quote\"slash\\tab\t.basm";
put($escape, "nop");
($v, $o) = explained($escape);
check($o->{$v->{records}[0]{origin}}{file} eq $escape, 'JSON path escaping round-trips');

sub rejected {
    my ($src, @opts) = @_;
    unlink "$tmp/rejected.o";
    my ($rc, $out, $err) = run('--target-profile', 'public', '--diagnostics-json', @opts,
        '-f', 'elf64', '-o', "$tmp/rejected.o", $src);
    check($rc != 0 && !-e "$tmp/rejected.o" && $out eq '', 'error publishes neither object nor explanation');
    my $d = decode_json($err);
    check($d->{severity} eq 'error' && length($d->{message}), 'structured error');
    return $d;
}
put($escape, "bits 64\nnop\nnot_an_instruction\n");
my $d = rejected($escape);
check($d->{file} eq $escape && $d->{line} == 3, 'raw JSON diagnostic location');
put("$incdir/bad.inc", "%macro BAD 0\nnop\nnot_an_instruction\n%endmacro\n");
put($source, "%include \"bad.inc\"\n%rep 0\nnop\n%endrep\nBAD\n");
$d = rejected($source, '--explain', '-I', $incdir);
check($d->{file} eq "$incdir/bad.inc" && $d->{line} == 3, 'parser error maps to macro definition');
check(@{$d->{expansion_chain}} == 2 && $d->{expansion_chain}[1]{file} eq $source &&
      $d->{expansion_chain}[1]{line} == 5, 'diagnostic caller location after skipped body');
put($escape, "%macro UNUSED 0\nnop\n%endmacro\n%rep 0\nnop\n%endrep\n%endif\n");
$d = rejected($escape, '--explain');
check($d->{file} eq $escape && $d->{line} == 7, 'preprocessor error raw cursor after skipped bodies');

put($source, "%macro DEFERRED 0\n%include \"leaf.inc\"\n%endmacro\nDEFERRED\n");
$d = rejected($source, '--explain', '-I', $incdir);
check($d->{message} =~ /outside traced preprocessor/, 'deferred include explicitly refused');
put($source, "%rep 65537\nnop\n%endrep\n");
$d = rejected($source, '--explain');
check($d->{message} =~ /intent .*limit/, 'bounded origin/record allocation refuses excess');

print "PASS intent trace: $checks structural checks; partial CFG, semantic verification unimplemented\n";
PERL
