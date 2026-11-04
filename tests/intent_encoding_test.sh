#!/bin/sh
# INV-595: actual product encodings match the independent assembler oracle.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
exec perl - "${BASM:-$ROOT/basm}" "${NASM:-nasm}" "$ROOT" <<'PERL'
use strict; use warnings;
use File::Temp qw(tempdir);
my ($basm,$nasm,$root)=@ARGV;
my $tmp=tempdir('basm-intent-encode-XXXXXX',TMPDIR=>1,CLEANUP=>!$ENV{INTENT_KEEP});
print STDERR "intent fixture: $tmp\n" if $ENV{INTENT_KEEP};
sub put { open my $f,'>',$_[0] or die $!; print {$f} $_[1]; close $f or die $! }
sub get { open my $f,'<:raw',$_[0] or die $!; local $/; return <$f> // '' }
my $checks=0;
sub check { die "FAIL intent encoding: $_[1]\n" unless $_[0]; $checks++ }
sub run {
    my ($tool,@args)=@_;
    my $pid=fork(); defined $pid or die $!;
    if(!$pid){ open STDERR,'>',"$tmp/error" or die $!; open STDOUT,'>',"$tmp/stdout" or die $!; exec {$tool} $tool,@args; die $! }
    waitpid($pid,0); return $?;
}
open my $f,'<',"$root/isa/forms.tsv" or die $!;
my $header=<$f>; my @rows=map { chomp; [split /\t/,$_,-1] } <$f>;
close $f;
my %regs=(8=>[qw(al bl ah ch spl dil r8b r15b)],16=>[qw(ax bx r8w r15w)],
          32=>[qw(eax ebx r8d r15d)],64=>[qw(rax rbx r8 r15)]);
my $source="bits 64\nsection .text\n";
for my $r (@rows){
    if($r->[10] eq 'fixed'){ $source.="$r->[1]\n"; next }
    if($r->[10] =~ /^sse_/){
        my %ops=(sse_rr=>'xmm15,xmm8',sse_rm=>'xmm15,[r13+128]',sse_mr=>'[r13+128],xmm15',
                 sse_xg=>'xmm15,r8',sse_gx=>'r15,xmm8',sse_shift=>'xmm15,16',sse_shuf=>'xmm15,xmm8,50');
        $source.="$r->[1] $ops{$r->[10]}\n"; next;
    }
    my @rs=@{$regs{$r->[9]}};
    if($r->[10] eq 'gpr_rotate'){
        my ($count)=$r->[2]=~/^gpr,([18])$/; defined $count or die 'unbounded rotate';
        $source.="$r->[1] $_,$count\n" for @rs;
        next;
    }
    for my $a (@rs){ for my $b (@rs){
        next if $r->[9]==8 && (($a=~/^[abcd]h$/ && $b=~/^(?:spl|dil|r)/) ||
                               ($b=~/^[abcd]h$/ && $a=~/^(?:spl|dil|r)/));
        $source.="$r->[1] $a, $b\n";
    }}
}
$source.="jmp \$\njne \$\nloop \$\ncall \$\n";
$source.="o64 sysret\nafter_sysret: nop\no64 iret\nafter_iret: nop\n";
put("$tmp/valid.basm",$source);
my $oracle=$source;
$oracle=~s/^sysretq$/o64 sysret/mg; # NASM 2.x otherwise treats this spelling as an orphan label.
put("$tmp/oracle.basm",$oracle);
check(run($nasm,'-w+error=orphan-labels','-f','bin','-o',"$tmp/nasm.bin","$tmp/oracle.basm")==0,'NASM oracle accepted fixture');
for my $profile ('public','beyond') {
    check(run($basm,'--target-profile',$profile,'-f','bin','-o',"$tmp/product.bin","$tmp/valid.basm")==0,
          "$profile valid forms: ".get("$tmp/error"));
    my ($actual,$expected)=(get("$tmp/product.bin"),get("$tmp/nasm.bin"));
    if($actual ne $expected){
        my $i=0; $i++ while $i<length($actual) && $i<length($expected) && substr($actual,$i,1) eq substr($expected,$i,1);
        die "FAIL intent encoding: $profile differs at $i: product=".unpack('H*',substr($actual,$i,16)).
            " nasm=".unpack('H*',substr($expected,$i,16))."\n";
    }
    check(1,"$profile bytes match NASM");
    for my $bad ('mov rax, ebx','mov ah, r8b','mov spl, ah','add eax, rbx',
                 'xor bh, r9b','cmp al, ax','nop rax','cpuid rbx','ret 8',
                 'mov rax, rbx, rcx','add rax, rbx, rcx') {
        put("$tmp/bad.basm","bits 64\nsection .text\n$bad\n");
        unlink "$tmp/rejected.bin";
        my $rc=run($basm,'--target-profile',$profile,'-f','bin','-o',"$tmp/rejected.bin","$tmp/bad.basm");
        check($rc==256 && !-e "$tmp/rejected.bin","$profile rejects $bad without output");
    }
}
print "PASS intent encoding ($checks checks; all schema forms plus register cross-products)\n";
PERL
