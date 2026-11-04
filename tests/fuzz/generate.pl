#!/usr/bin/env perl
# W1/INV-578: deterministic differential fuzz generator, BearBasm vs NASM.
# Prints one random assembly program to stdout. Same seed => same stream.
use strict;
use warnings;
my ($seed, $count) = @ARGV;
$seed //= 1; $count //= 1;
my $st = $seed & 0x7fffffff;
sub rnd { $st = ($st * 1103515245 + 12345) & 0x7fffffff; return $st; }
sub pick { return $_[rnd() % @_]; }
my @r64 = qw(rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15);
my @r32 = qw(eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d);
my @alu = qw(add or and sub xor cmp);
for (my $c = 0; $c < $count; $c++) {
    print "bits 64\nsection .text\nglobal fuzz_entry\nfuzz_entry:\n";
    my $n = 3 + rnd() % 14;
    my @labels = ();
    for (my $i = 0; $i < $n; $i++) {
        my $k = rnd() % 100;
        if ($k < 28) {
            my ($d, $s) = ($r64[rnd() % @r64], $r64[rnd() % @r64]);
            print "    mov $d, $s\n";
        } elsif ($k < 44) {
            my ($d, $s) = ($r32[rnd() % @r32], $r32[rnd() % @r32]);
            print "    mov $d, $s\n";
        } elsif ($k < 62) {
            my $op = pick(@alu);
            my $d = pick(@r64);
            if (rnd() % 2) {
                my $s = pick(@r64);
                print "    $op $d, $s\n";
            } else {
                my $imm = rnd() % 300 - 100;
                $imm = sprintf("0x%x", rnd() % 0xffffff) if rnd() % 3 == 0;
                print "    $op $d, $imm\n";
            }
        } elsif ($k < 68) {
            print "    push " . pick(@r64) . "\n" if rnd() % 2;
            print "    pop " . pick(@r64) . "\n";
        } elsif ($k < 73) {
            print "    nop\n";
        } elsif ($k < 80) {
            my $L = "L${c}_$i";
            push @labels, $L;
            print "    cmp rax, " . (rnd() % 50) . "\n";
            print "    " . pick(qw(je jne jb jae)) . " $L\n";
            print "    nop\n" if rnd() % 2;
            print "$L:\n" if rnd() % 2;
        } elsif ($k < 86) {
            if (@labels && rnd() % 2) {
                print "    jmp " . $labels[rnd() % @labels] . "\n";
            } else {
                print "    mov rax, [rel .rodata]\n" if 0;
                print "    lea rax, [rel d$c\_$i]\n";
                print "section .rodata\nd$c\_$i: dq " . (rnd() % 100000) . "\nsection .text\n";
            }
        } elsif ($k < 92) {
            print "    db " . join(",", map { rnd() % 256 } 1..(1 + rnd() % 4)) . "\n";
            print "    times " . (1 + rnd() % 5) . " db 0x90\n" if rnd() % 3 == 0;
        } else {
            print "    align " . pick(1, 2, 4, 8, 16) . "\n";
        }
    }
    for my $L (@labels) { print "$L:\n" if rnd() % 3 == 0; }
    print "    ret\n";
    print "%%CASE%%\n" if $c + 1 < $count;
}
