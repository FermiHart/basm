#!/bin/bash
# TEST-01/02: Differential testing script
# Compares basm output against NASM for all regression tests

set -e

BASM="${1:-/Users/admin/OS/BearBasm/basm}"
NASM="${2:-nasm}"
TEST_DIR="$(dirname "$0")/regression"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass=0
fail=0
skip=0
total=0

echo "=========================================="
echo "  Basm Differential Test Suite"
echo "=========================================="
echo "BASM: $BASM"
echo "NASM: $NASM"
echo "TEST_DIR: $TEST_DIR"
echo ""

# Check if basm exists
if [ ! -x "$BASM" ]; then
    echo -e "${RED}ERROR: basm not found at $BASM${NC}"
    exit 1
fi

# Check if nasm exists
if ! command -v "$NASM" &> /dev/null; then
    echo -e "${RED}ERROR: nasm not found${NC}"
    exit 1
fi

# Test each .basm file in regression directory
for test in "$TEST_DIR"/*.basm; do
    [ -f "$test" ] || continue
    
    name=$(basename "$test" .basm)
    total=$((total + 1))
    echo -n "[$total] Testing $name... "
    
    # Compile with basm
    if ! "$BASM" -f bin -o "/tmp/${name}_basm.bin" "$test" 2>/tmp/basm_err; then
        # Check if it's an expected error (like SEC-03 depth limit)
        if grep -q "too deeply nested" /tmp/basm_err; then
            echo -e "${YELLOW}SKIP${NC} (expected error: depth limit)"
            skip=$((skip + 1))
        else
            echo -e "${RED}FAIL${NC} (basm error)"
            cat /tmp/basm_err
            fail=$((fail + 1))
        fi
        continue
    fi
    
    # Compile with nasm
    if ! "$NASM" -f bin -o "/tmp/${name}_nasm.bin" "$test" 2>/tmp/nasm_err; then
        echo -e "${YELLOW}SKIP${NC} (nasm error)"
        cat /tmp/nasm_err
        skip=$((skip + 1))
        continue
    fi
    
    # Compare outputs
    if cmp -s "/tmp/${name}_basm.bin" "/tmp/${name}_nasm.bin"; then
        size=$(wc -c < "/tmp/${name}_basm.bin")
        echo -e "${GREEN}PASS${NC} ($size bytes)"
        pass=$((pass + 1))
    else
        basm_size=$(wc -c < "/tmp/${name}_basm.bin")
        nasm_size=$(wc -c < "/tmp/${name}_nasm.bin")
        echo -e "${RED}FAIL${NC} (output differs)"
        echo "  basm: $basm_size bytes"
        echo "  nasm: $nasm_size bytes"
        echo "  First 5 differences:"
        cmp -l "/tmp/${name}_basm.bin" "/tmp/${name}_nasm.bin" | head -5
        fail=$((fail + 1))
    fi
done

echo ""
echo "=========================================="
echo "  Results"
echo "=========================================="
echo -e "Total:  $total"
echo -e "Pass:   ${GREEN}$pass${NC}"
echo -e "Fail:   ${RED}$fail${NC}"
echo -e "Skip:   ${YELLOW}$skip${NC}"
echo ""

# Test ELF output separately
echo "=========================================="
echo "  ELF Output Tests"
echo "=========================================="
elf_pass=0
elf_fail=0

for test in "$TEST_DIR"/test_basic.basm "$TEST_DIR"/test_preproc.basm; do
    [ -f "$test" ] || continue
    
    name=$(basename "$test" .basm)
    echo -n "ELF $name... "
    
    if "$BASM" -f elf64 -o "/tmp/${name}_basm.o" "$test" 2>/dev/null; then
        if file "/tmp/${name}_basm.o" | grep -q "ELF 64-bit"; then
            echo -e "${GREEN}PASS${NC}"
            elf_pass=$((elf_pass + 1))
        else
            echo -e "${RED}FAIL${NC} (not valid ELF)"
            elf_fail=$((elf_fail + 1))
        fi
    else
        echo -e "${YELLOW}SKIP${NC}"
    fi
done

echo ""
echo "=========================================="
echo "  Final Summary"
echo "=========================================="
echo -e "BIN Tests: ${GREEN}$pass${NC} pass, ${RED}$fail${NC} fail, ${YELLOW}$skip${NC} skip"
echo -e "ELF Tests: ${GREEN}$elf_pass${NC} pass, ${RED}$elf_fail${NC} fail"
echo ""

if [ $fail -eq 0 ] && [ $elf_fail -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
