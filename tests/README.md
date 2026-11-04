# Basm Regression Test Suite

This directory contains regression tests for the basm assembler, ensuring compatibility with NASM output.

## Running Tests

```bash
./diff_test.sh
```

Or specify custom paths:

```bash
./diff_test.sh /path/to/basm /path/to/nasm
```

## Test Categories

### Basic Tests
- **test_basic.basm**: Fundamental x86 instructions (mov, add, sub, jmp, call)
- **test_addressing.basm**: Complex memory addressing modes
- **test_preproc.basm**: Preprocessor features (%define, %macro, %if, %assign)

### Bug Fix Verification
- **test_bug07_movzx.basm**: BUG-07 - movzx/movsx with explicit size keywords
- **test_bug08_lea.basm**: BUG-08 - lea with displacement-only in BITS 32
- **test_bug09_jmpfar.basm**: BUG-09 - jmp far with label in bin format
- **test_bug10_call.basm**: BUG-10 - call forward label displacement
- **test_bug11_push.basm**: BUG-11 - push imm with label apply g_org
- **test_bug12_movmem.basm**: BUG-12 - mov [mem], imm resolve labels in bin

### Security Tests
- **test_sec03_depth.basm**: SEC-03 - recursion depth limit in parse_expr

## Test Methodology

Parity tests compare `.text` byte-for-byte and normalized symbols/relocations
through `elftool`. Flat binary tests compare the complete output bytes.

For ELF tests, the output is validated to ensure it's a proper ELF 64-bit relocatable file.

## Expected Results

Parity-class tests must satisfy `POLITICA-BASM.md`: identical `.text`, normalized
symbols and relocations. Full ELF-file identity is desirable but not normative;
extensions and prohibited inputs follow their manifest classification.

## Adding New Tests

1. Create a new `.basm` file in the `regression/` directory
2. Ensure it compiles with both basm and NASM
3. Run `./diff_test.sh` to verify
4. Commit the test file

## Test Output Format

```
[1] Testing test_name... PASS (42 bytes)
```

- **PASS**: Output matches NASM exactly
- **FAIL**: Output differs (shows first 5 byte differences)
- **SKIP**: Expected error or NASM incompatibility
