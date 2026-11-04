#!/bin/sh
# INV-589: production assembly selects Beyond; only the exact AP caller opts in.
# Static only: do not evaluate root Makefiles or rebuild tools/production objects.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/../../.." && pwd)
perl - "$ROOT" <<'PERL'
use strict;
use warnings;

my $root = shift;
my $ap = 'ring0/arch/amd64/ap_trampoline.basm';
my %expected = (
    # INV-621: agent-userland delegates shell assembly to the canonical rule.
    'Makefile' => [13, 0],
    'Makefile.sovereign' => [3, 3],
    'Makefile.jash' => [1, 0],
);
my @errors;
for my $file (sort keys %expected) {
    open my $fh, '<', "$root/$file" or die "$file: $!\n";
    my $text = do { local $/; <$fh> };
    # Join continuations without invoking $(shell), includes or recursive make.
    $text =~ s/\\\n[ \t]*/ /g;
    my (%deps, %recipes, @rules);
    my $rule;
    my @active;
    for my $line (split /\n/, $text) {
        next if $line =~ /^\s*(?:#|$)/;
        push @active, $line;
        if ($line =~ /^\t/) {
            $recipes{$rule} .= "$line\n" if defined $rule;
        } elsif ($line =~ /^(?:override\s+)?[\w.-]+\s*[:?+]?=/) {
            undef $rule;
        } elsif ($line =~ /^(\S.*?)\s*:\s*(.*)$/) {
            ($rule, my $prereqs) = ($1, $2);
            push @rules, $rule unless exists $deps{$rule};
            $deps{$rule} .= " $prereqs";
        } else {
            undef $rule;
        }
    }
    my $active = join "\n", @active;
    my @basm_defs = $active =~ /^((?:override\s+)?BASM\s*[:?+]?=.*)$/mg;
    push @errors, "$file: BASM must be the pinned executable, not PATH or flags"
        unless @basm_defs == 1 && $basm_defs[0] =~
            /^override\s+BASM\s*:=\s*\$\(CURDIR\)\/toolchain\/BearBasm\/basm\s*$/;
    # INV-597: a tool prerequisite without an explicit recipe invites Make's
    # built-in `cc basm.c -o basm` under -B or on a missing executable.
    my $tool_recipe = $recipes{'$(BASM)'} // '';
    push @errors, "$file: missing explicit prebuilt sovereign tool guard"
        unless $tool_recipe =~ /test\s+-x\s+"\$\@"/ &&
               $tool_recipe !~ /\b(?:cc|gcc|clang)\b/;

    my ($assembly, $verify, $bootstrap) = (0, 0, 0);
    for my $target (@rules) {
        my $recipe = $recipes{$target} // '';
        my $where = "$file [$target]";
        my $has_assembly = 0;
        # Match commands, not echo/printf text, comments or doctor tool lists.
        while ($recipe =~ /(?:^|[;&|])\s*[\@+-]*\$\(BASM\)\s+([^;&|\n]*)/mg) {
            my $args = $1;
            if ($args =~ /--verify/) {
                ++$verify;
                push @errors, "$where: verifier received assembly policy options"
                    if $args =~ /--target-profile|--bootstrap|\$\$bootstrap/;
                next;
            }
            ++$assembly;
            $has_assembly = 1;
            my @profiles = $args =~ /--target-profile\s+(\S+)/g;
            push @errors, "$where: assembly must select --target-profile beyond once"
                unless @profiles == 1 && $profiles[0] eq 'beyond';
            my $source = $file eq 'Makefile.sovereign' && $target eq '%.o' ? '$<' :
                $file eq 'Makefile.sovereign' && $target eq 'signed-basmproofs' ? '$$src' : '';
            if ($source) {
                ++$bootstrap;
                my $guard = 'bootstrap=""; if [ "' . $source . '" = "' . $ap .
                    '" ]; then bootstrap="--bootstrap ap-trampoline-v1"; fi;';
                my $rest = $recipe;
                my $guards = $rest =~ s/\Q$guard\E//g;
                push @errors, "$where: bootstrap must reset and test the exact AP source"
                    unless $guards == 1 && $recipe =~ /\Q$guard\E\s*\$\(BASM\)/;
                push @errors, "$where: assembly must consume the AP-only bootstrap options"
                    unless $args =~ /(?:^|\s)\$\$bootstrap(?:\s|$)/ &&
                        $args =~ /(?:^|\s)"?\Q$source\E"?\s*$/;
                $rest =~ s/\$\$bootstrap//g;
                push @errors, "$where: bootstrap options escape the exact-source guard"
                    if $rest =~ /bootstrap/;
            } elsif ($args =~ /--bootstrap|\$\$bootstrap/) {
                push @errors, "$where: non-AP assembly has bootstrap options";
            }
        }
        next unless $has_assembly;
        my $prereqs = $deps{$target};
        if ($file eq 'Makefile.sovereign' && $target eq '%.o') {
            # Scope the tool edge to production objects, not the assembler's own .o.
            $prereqs = $deps{'$(ASM_OBJECTS)'} // '';
            push @errors, "$where: source must remain the first implicit prerequisite"
                unless $deps{$target} =~ /^\s*%\.basm(?:\s|$)/;
        }
        my ($normal) = split /\|/, $prereqs;
        $normal //= '';
        push @errors, "$where: missing normal prerequisite on the actual BASM binary"
            unless $normal =~ /(?:^|\s)\$\(BASM\)(?:\s|$)/;
    }
    push @errors, "$file: expected $expected{$file}[0] assembly commands, found $assembly"
        unless $assembly == $expected{$file}[0];
    push @errors, "$file: expected $expected{$file}[1] verifiers, found $verify"
        unless $verify == $expected{$file}[1];
    my @bootflags = $active =~ /--bootstrap\b/g;
    push @errors, "$file: bootstrap selector outside the two AP-aware callers"
        unless @bootflags == $bootstrap && $bootstrap == ($file eq 'Makefile.sovereign' ? 2 : 0);
    for my $target (@rules) {
        push @errors, "$file: circular BASM prerequisite"
            if $target =~ /\$\(BASM\)/ && $deps{$target} =~ /\$\(BASM\)/;
    }
    printf "%s: %d assembly commands, %d verifiers, %d AP guards checked\n",
        $file, $assembly, $verify, $bootstrap;
}
if (@errors) {
    print STDERR "FAIL build profile callers: $_\n" for @errors;
    exit 1;
}
print "PASS build profile callers (profiles, AP-only bootstrap, verifier isolation, pinned tool dependencies)\n";
PERL
