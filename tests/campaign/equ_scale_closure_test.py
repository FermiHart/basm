#!/usr/bin/env python3
"""N26 closure: scalar EQU contract and bounded memory scales, without code execution.

NASM-supported relocatable EQU aliases are intentionally refused by BearBasm;
these cases are recorded as compatibility limits, not as passing parity cases.
"""
import relocation_nasm_test as suite

STACK, DATA, EXTERNAL = suite.STACK, suite.DATA, suite.EXTERNAL


def closure_cases(_wave):
    yield {
        "name": "N26-equ-local-alias", "basm_only_rejection": True,
        "source": "bits 64\nsection .data\nvalue: dq alias\nlocal: dd 0\nalias equ local\n" + STACK,
        "fields": [(".data", "value", 0, 8, DATA + 8)],
    }
    yield {
        "name": "N26-equ-alias-chain", "basm_only_rejection": True,
        "source": "bits 64\nsection .data\nvalue: dq a\na equ b\nb equ local\nlocal: dd 0\n" + STACK,
        "fields": [(".data", "value", 0, 8, DATA + 8)],
    }
    yield {
        "name": "N26-equ-location-alias", "basm_only_rejection": True,
        "source": "bits 64\nsection .data\ndd 0\nhere equ $\nvalue: dq here\n" + STACK,
        "fields": [(".data", "value", 0, 8, DATA + 4)],
    }
    yield {
        "name": "N26-equ-external-alias", "basm_only_rejection": True,
        "source": "bits 64\nextern external_target\nalias equ external_target+7\nsection .data\nvalue: dq alias\n" + STACK,
        "fields": [(".data", "value", 0, 8, EXTERNAL + 7)],
    }
    yield {
        "name": "N26-equ-forward-difference",
        "source": "bits 64\nsection .data\nvalue: dq delta\ndelta equ end-start\nstart: db 0,0,0\nend: db 0\n" + STACK,
        "fields": [(".data", "value", 0, 8, 3)],
    }
    yield {
        "name": "N26-equ-forward-literal-chain",
        "source": "bits 64\nsection .data\nvalue: dd first\nfirst equ second+1\nsecond equ 3\n" + STACK,
        "fields": [(".data", "value", 0, 4, 4)],
    }
    yield {
        "name": "N26-equ-contextual-difference",
        "source": "bits 64\nsection .data\ndb 0,0,0\ndelta equ $-$$\nvalue: dd delta\n" + STACK,
        "fields": [(".data", "value", 0, 4, 3)],
    }
    yield {
        "name": "N26-equ-external-cancellation",
        "source": "bits 64\nextern external_target\nzero equ external_target-external_target\nsection .data\nvalue: dq zero\ndq external_target\n" + STACK,
        "fields": [(".data", "value", 0, 8, 0)],
    }
    yield {
        "name": "N26-equ-cycle", "basm_only_rejection": True,
        "source": "bits 64\na equ b\nb equ a\nsection .data\nvalue: dq a\n" + STACK,
        "fields": [(".data", "value", 0, 8, 0)],
    }
    yield {
        "name": "N26-equ-bin-known-alias", "format": "bin", "basm_only_rejection": True,
        "source": "bits 64\norg 0x7000\ndq alias\nlocal: db 0\nalias equ local\n",
    }
    yield {
        "name": "N26-scale-valid-register-and-constant",
        "source": "bits 64\nsection .text\nmov eax,[rax+rcx*4]\nmov edx,[rbx+511*7]\nmov r9d,[eax+ecx*8]\n" + STACK,
    }
    yield {
        "name": "N26-scale-forward-constant", "nasm_only_rejection": True,
        "source": "bits 64\nsection .text\nmov eax,[rax+rcx*factor]\nfactor equ 4\n" + STACK,
        "expected_section_hex": {".text":"8b0488"},
    }
    for name, address in (("narrowing-to-one", "rbx+rax*4294967297"),
                          ("narrowing-to-eight", "rbx+rax*4294967304"),
                          ("three-registers", "rax+rbx+rcx"),
                          ("negative-register", "rax-rbx"),
                          ("external-scale", "rax+rcx*external_target"),
                          ("external-constant-product", "rax+511*external_target")):
        narrow=name.startswith("narrowing")
        yield {
            "name": "N26-scale-reject-" + name, "assembly_failure": not narrow,
            "basm_only_rejection": narrow,
            "rejection_status": "BASM_REFUSAL_NASM_NARROWED_SCALE",
            "expected_section_hex": ({".text":"8b0403" if name=="narrowing-to-one" else "8b04c3"} if narrow else {}),
            "source": "bits 64\nextern external_target\nsection .text\nmov eax,[" + address + "]\n" + STACK,
        }
    yield {
        "name":"N26-scale-bin-local-nonunit", "format":"bin", "assembly_failure":True,
        "source":"bits 64\ndb 0\nlocal: db 0\nmov eax,[rbx+rax*(local*2)]\n",
    }
    for name,address in (("rsp-scaled","rax+rsp*2"),("esp-scaled","eax+esp*2")):
        yield {
            "name":"N26-scale-reject-"+name, "assembly_failure":True,
            "source":"bits 64\nsection .text\nmov eax,["+address+"]\n"+STACK,
        }
    yield {
        "name":"N26-scale-stack-base-and-r12-index",
        "source":"bits 64\nsection .text\nmov eax,[rax+rsp]\nmov eax,[r12+rsp]\nmov eax,[rax+r12*2]\nmov eax,[eax+esp]\n"+STACK,
    }


def retained_cases(wave):
    for case in closure_cases(wave):
        case["preserve_existing_basm"]=True
        yield case


if __name__ == "__main__":
    suite.cases=retained_cases
    suite.main()
