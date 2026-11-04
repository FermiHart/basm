#!/usr/bin/env perl
# W4: branch-farm generator. Sweeps padding across the rel8/rel32 boundary
# (100..140 bytes) in both directions, plus chains, calls and loops, so any
# fixpoint under/overshoot shows as a wrong symbolic target downstream.
use strict;
use warnings;
my ($seed, $count) = @ARGV;
$seed //= 1; $count //= 1;
my $st = $seed & 0x7fffffff;
sub rnd { $st = ($st * 1103515245 + 12345) & 0x7fffffff; return $st; }
for (my $c = 0; $c < $count; $c++) {
    print "bits 64\nsection .text\nglobal farm$c\nfarm$c:\n";
    my $pads = 2 + rnd() % 6;
    for (my $p = 0; $p < $pads; $p++) {
        my $T = "T${c}_${p}";
        my $pad = 60 + rnd() % 120;
        my $cc = (qw(je jne jb jae jz jnz))[rnd() % 6];
        print "    cmp rax, " . (rnd() % 200) . "\n";
        if (rnd() % 2) {
            print "    $cc $T\n";
            print "    times $pad db 0x90\n";
            print "$T:\n";
            print "    nop\n" if rnd() % 2;
        } else {
            print "$T:\n";
            print "    nop\n" if rnd() % 2;
            print "    times $pad db 0x90\n";
            print "    cmp rbx, " . (rnd() % 200) . "\n";
            print "    $cc $T\n";
        }
    }
    my $want_call = rnd() % 2;
    my $want_loop = rnd() % 3 == 0;
    print "    call sub$c\n" if $want_call;
    if ($want_loop) {
        print "    mov ecx, " . (1 + rnd() % 10) . "\nloop$c:\n";
        print "    dec ecx\n    jnz loop$c\n";
    }
    print "    ret\n";
    print "sub$c:\n    ret\n" if $want_call;
    print "%%CASE%%\n" if $c + 1 < $count;
}
