#!/usr/bin/env python3
"""N14–N18: assembly-only differential and preprocessor lifetime regressions.

The small C probe inspects preprocessing state; it never executes assembled code.
All process commands, diagnostics, identities and output bytes are retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''#define main basm_unused_main
#include "basm.c"
#undef main
static char *owned(const char *s) {
    size_t n=strlen(s)+1; char *p=malloc(n); if (!p) return NULL;
    memcpy(p,s,n); return p;
}
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    g_srcname=g_file="synthetic-probe";
    const char *source="section .text\nmov rax,[rbx+rcx*4]\nret\n";
    if (!strcmp(argv[1],"brackets")) {
        char *in=owned(source); char *out=preprocess(in,(long)strlen(in));
        if (out!=in || strcmp(out,source) || g_line!=3) return 3;
        if (pp_work_steps!=6 || pp_work_bytes!=2*strlen(source)) return 4;
        const BasmDependency *dep=basm_dependency_at(0);
        if (basm_dependency_count()!=1 || dep->len!=strlen(source) ||
            memcmp(dep->data,source,dep->len)) return 5;
        free(out);
    } else if (!strcmp(argv[1],"final-newline")) {
        char *in=owned("mov rax,[rbx]"); char *out=preprocess(in,(long)strlen(in));
        if (strcmp(out,"mov rax,[rbx]\n")) return 6;
        free(out);
    } else if (!strcmp(argv[1],"bracket-directive")) {
        char *in=owned("[BITS 64]\nmov rax,[rbx]\n");
        char *out=preprocess(in,(long)strlen(in));
        if (strcmp(out,"bits 64\nmov rax,[rbx]\n")) return 7;
        free(out);
    } else if (!strcmp(argv[1],"origins")) {
        g_explain=1; g_target_profile=2;
        char *in=owned(source); char *out=preprocess(in,(long)strlen(in));
        if (out==in || strcmp(out,source) || !g_intent_norigins) return 8;
        free(out); intent_trace_free();
    } else if (!strcmp(argv[1],"work-budget")) {
        const size_t lines=PP_WORK_STEPS_MAX/2+1;
        char *in=malloc(lines+32); if (!in) return 9;
        memcpy(in,"mov rax,[rbx]\n",14);
        memset(in+14,'\n',lines-1); in[lines+13]=0;
        preprocess(in,(long)(lines+13)); return 10;
    } else if (!strcmp(argv[1],"argument-lifetime")) {
        const char *text="  (1+2), \"quoted,comma\", last  ; comment";
        PPArg args[3]; const char *cursor=text;
        int count=pp_parse_args(&cursor,args,3,0);
        if (count!=3 || args[0].len!=5 || args[1].len!=14 || args[2].len!=4) return 12;
        if (pp_arena_bytes || args[0].text!=text+2 ||
            memcmp(args[1].text,"\"quoted,comma\"",14)) return 13;
        for (int i=0;i<100000;i++) {
            cursor=text;
            if (pp_parse_args(&cursor,args,3,0)!=3) return 14;
        }
        if (pp_arena_bytes) return 15;
    } else if (!strcmp(argv[1],"dependency-index")) {
        char key[1024]; memset(key,'x',sizeof(key)); key[1000]=0;
        for (size_t i=0;i<BASM_DEP_COUNT_MAX;i++) {
            snprintf(key+980,20,"-%zu",i);
            const BasmDependency *dep=basm_snapshot_record(key,"data",4,BASM_DEP_INCBIN);
            if (dep!=basm_dependency_at(i)) return 16;
            if (i<8 && g_basm_path_index.cap) return 17;
        }
        if (g_basm_path_index.cap!=2*BASM_DEP_COUNT_MAX) return 18;
        for (size_t i=BASM_DEP_COUNT_MAX;i>0;i--) {
            snprintf(key+980,20,"-%zu",i-1);
            const BasmDependency *dep=basm_snapshot_find(key);
            if (dep!=basm_dependency_at(i-1) || memcmp(dep->data,"data",4)) return 19;
            if (basm_snapshot_record(key,"changed",7,BASM_DEP_INCBIN)!=dep) return 20;
        }
        if (basm_snapshot_find("absent") || basm_dependency_count()!=BASM_DEP_COUNT_MAX) return 21;
    } else if (!strcmp(argv[1],"request-index")) {
        for (int i=0;i<64;i++) {
            char name[64]; snprintf(name,sizeof(name),"request-%d.inc",i);
            FILE *f=fopen(name,"wb"); if (!f) return 22;
            if (fwrite("db 7\n",1,5,f)!=5 || fclose(f)) return 23;
            long size=0; int file=-1;
            const char *data=pp_read_include_file(name,&size,&file);
            if (size!=5 || data!=(const char *)basm_snapshot_find(name)->data) return 24;
            f=fopen(name,"wb"); if (!f) return 25;
            if (fwrite("db 8\n",1,5,f)!=5 || fclose(f)) return 26;
            const BasmDependency *other=basm_snapshot_open(name,BASM_DEP_INCBIN);
            if ((const char *)other->data!=data || memcmp(data,"db 7\n",5)) return 27;
            if (remove(name)) return 28;
            if (pp_read_include_file(name,&size,&file)!=data ||
                basm_snapshot_open(name,BASM_DEP_INCBIN)!=other) return 29;
        }
        if (g_basm_nrequests!=128 || !g_basm_request_index.cap) return 30;
        basm_dependencies_reset();
        if (g_basm_path_index.cap || g_basm_request_index.cap ||
            g_basm_path_index.slots || g_basm_request_index.slots) return 31;
    } else if (!strcmp(argv[1],"output-capacity")) {
        pp_cap=pp_len=(size_t)40*1024*1024; pp_out=malloc(pp_cap);
        if (!pp_out) return 32;
        pp_out[0]='a'; pp_out[pp_len-1]='z';
        pp_reserve(1);
        if (pp_cap!=PP_OUTPUT_BYTES_MAX || pp_out[0]!='a' || pp_out[pp_len-1]!='z') return 33;
        free(pp_out); pp_out=NULL; pp_cap=pp_len=0;
    } else if (!strcmp(argv[1],"output-budget")) {
        pp_len=PP_OUTPUT_BYTES_MAX; pp_reserve(1); return 34;
    } else if (!strcmp(argv[1],"definition-storage")) {
        pp_define_offset("COUNT",42);
        char *first=pp_defs[0].value; size_t used=g_pp_arena->used;
        for (int i=0;i<100000;i++) pp_define_offset("COUNT",42+i%10);
        if (pp_defs[0].value!=first || g_pp_arena->used!=used ||
            strcmp(pp_defs[0].value,"51") || pp_ndef!=1) return 35;
        pp_define_offset("COUNT",123456789);
        if (strcmp(pp_defs[0].value,"123456789")) return 36;
        first=pp_defs[0].value; pp_define_offset("COUNT",1);
        if (pp_defs[0].value!=first || strcmp(pp_defs[0].value,"1")) return 37;
    } else if (!strcmp(argv[1],"job-reset")) {
        const char *text="%define N 7\n%macro M 1\ndb %1\n%endmacro\n"
            "struc S\n.a resb 1\nendstruc\n@@:\nM N\ndb S_size\n";
        char *expected=NULL;
        for (int job=0;job<2;job++) {
            char *in=owned(text); char *out=preprocess(in,(long)strlen(in));
            if (pp_out || pp_len || pp_cap || !pp_ndef || !pp_nmac || !g_nstructs) return 38;
            if (!job) expected=owned(out);
            if (strcmp(expected,out)) return 39;
            arena_reset(); basm_dependencies_reset();
            if (pp_ndef || pp_nmac || pp_llabel || g_nstructs || pp_arena_bytes ||
                pp_work_bytes || pp_work_steps || pp_defs[0].value || pp_macs[0].body) return 40;
            if (strcmp(expected,out)) return 41;
            free(out);
        }
        free(expected);
    } else return 11;
    basm_dependencies_reset(); arena_reset(); return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cc", default="/usr/bin/x86_64-linux-gnu-gcc-13")
    parser.add_argument("--sanitize-probe", action="store_true")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "BASM-N14-N18-PREPROCESSOR-v1", "tests": [], "commands": [],
              "scope": "assembly and host C state probes only; no emitted code execution",
              "sanitizer_environment": {name: os.environ.get(name) for name in
                  ("ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS")},
              "probe_source_inputs": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in [ROOT / "basm.c", *sorted((ROOT / "modules").glob("*.inc"))]}}
    for name, binary in (("basm", args.basm.resolve()), ("nasm", args.nasm.resolve())):
        content = binary.read_bytes()
        report[name] = {"path": str(binary), "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()}

    def run(name, command):
        result = subprocess.run(list(map(str, command)), cwd=output, capture_output=True, timeout=60)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        report["commands"].append({"name": name, "argv": list(map(str, command)),
                                   "returncode": result.returncode})
        return result

    cases = {
        "operand-brackets": "bits 64\nmov rax,[rbx+rcx*4]\nmov eax,[rax+8]\nret\n",
        "quoted-markers": 'bits 64\ndb "[ @ % struc",0\n',
        "missing-final-newline": "bits 64\nmov rax,[rbx]",
        "bracket-bits": "[BITS 64]\nmov rax,[rbx]\n",
        "command-define": "%define REG rbx\nbits 64\nmov rax,[REG]\n",
        "nested-rotation": "%macro INNER 2\ndb %1,%2\n%endmacro\n"
            "%macro OUTER 3\nINNER %1,%2\n%rotate 1\nINNER %1,%2\n"
            "%rotate -2\nINNER %1,%3\n%endmacro\nOUTER 1,2,3\n",
        "function-quoted-nesting": '%define F(a,b) a,b\ndb F("a,b",(1+2))\n',
        "conditional-argument-spans": "%ifidn one,one\ndb 1\n%endif\n"
            "%ifnidn one,two\ndb 2\n%endif\n",
        "repeated-includes": "".join(f'%include "part-{i}.inc"\n' for i in range(12)) * 2,
        "undef-to-plain": '%define FLAG 1\n%undef FLAG\ndb "ok",1\n',
        "macro-literal-markers": '%macro CONST 0\ndb "literal %+ @F"\n%endmacro\nCONST\n',
        "assign-in-repetition": "%assign x 0\n%rep 4\ndb x\n%assign x x+1\n%endrep\n",
        "redefine-grow-shrink": "%define X 123\ndq X\n%define X 1\ndq X\n"
            "%define X 123456789\ndq X\n%define X 2\ndq X\n",
    }
    for i in range(12):
        (output / f"part-{i}.inc").write_text(f"db {i}\n")
    for name, source in cases.items():
        path = output / (name + ".asm")
        path.write_text(source)
        emitted = []
        for lane, binary in (("basm", args.basm.resolve()), ("nasm", args.nasm.resolve())):
            artifact = output / (name + "." + lane + ".bin")
            result = run(name + "-" + lane, [binary, "-f", "bin", "-o", artifact, path])
            emitted.append((result.returncode, artifact.read_bytes() if artifact.exists() else None))
        ok = emitted[0][0] == emitted[1][0] == 0 and emitted[0][1] == emitted[1][1]
        report["tests"].append({"name": name, "pass": ok})

    probe_source = output / "probe.c"
    probe_source.write_text(PROBE)
    probe = output / "probe"
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-misleading-indentation", "-Wno-stringop-truncation", "-Wno-format-truncation",
               "-DSHA256NI_FORCE_SOFTWARE=1", "-ffunction-sections", "-fdata-sections",
               "-Wl,--gc-sections", "-I" + str(ROOT), probe_source, "-o", probe]
    if args.sanitize_probe:
        command += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    compiled = run("probe-compile", command)
    report["tests"].append({"name": "probe-compiles", "pass": compiled.returncode == 0})
    if not compiled.returncode:
        for mode in ("brackets", "final-newline", "bracket-directive", "origins", "work-budget",
                     "argument-lifetime", "dependency-index", "request-index", "output-capacity",
                     "output-budget", "definition-storage", "job-reset"):
            result = run("probe-" + mode, [probe, mode])
            diagnostic = {"work-budget": b"preprocessor work budget exceeded",
                          "output-budget": b"preprocessor output byte budget exceeded"}.get(mode)
            ok = result.returncode == 0 if diagnostic is None else (
                result.returncode == 1 and diagnostic in result.stderr)
            ok = ok and not any(marker in result.stderr for marker in
                (b"AddressSanitizer", b"LeakSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:"))
            report["tests"].append({"name": mode, "pass": ok})
    report["failed"] = sum(not record["pass"] for record in report["tests"])
    report["passed"] = len(report["tests"]) - report["failed"]
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failed": report["failed"], "evidence": str(output)}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
